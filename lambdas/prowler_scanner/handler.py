"""Prowler Scanner Lambda - Runs Prowler CIS AWS checks.

This Lambda:
1. Assumes cross-account role
2. Runs Prowler with CIS AWS 1.4 compliance checks
3. Parses JSON output
4. Normalizes findings to CloudSecure format
5. Returns findings for aggregation
"""

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")

# Prowler configuration
# Note: Prowler 5.x uses different framework names than 4.x
# cis_2.0_aws = CIS AWS Foundations Benchmark v2.0.0
PROWLER_COMPLIANCE_FRAMEWORK = "cis_2.0_aws"
PROWLER_TIMEOUT_SECONDS = 840  # 14 minutes (Lambda max is 15)

# All available checks (the full default set)
ALL_CHECKS = [
    # IAM
    "iam_root_mfa_enabled",
    "iam_root_hardware_mfa_enabled",
    "iam_no_root_access_key",
    "iam_user_mfa_enabled_console_access",
    "iam_password_policy_minimum_length_14",
    # CloudTrail
    "cloudtrail_multi_region_enabled",
    "cloudtrail_log_file_validation_enabled",
    "cloudtrail_cloudwatch_logging_enabled",
    # S3
    "s3_bucket_public_access",
    "s3_bucket_default_encryption",
    "s3_account_level_public_access_blocks",
    # EC2
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
    "ec2_ebs_default_encryption",
    # RDS
    "rds_instance_storage_encrypted",
    "rds_instance_no_public_access",
    # VPC
    "vpc_flow_logs_enabled",
]

# Maps scan scope values to Prowler check IDs
SCOPE_CHECKS = {
    "iam": [c for c in ALL_CHECKS if c.startswith("iam_")],
    "cloudtrail": [c for c in ALL_CHECKS if c.startswith("cloudtrail_")],
    "s3": [c for c in ALL_CHECKS if c.startswith("s3_")],
    "ec2": [c for c in ALL_CHECKS if c.startswith("ec2_")],
    "network": [
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
        "vpc_flow_logs_enabled",
    ],
    "rds": [c for c in ALL_CHECKS if c.startswith("rds_")],
    "vpc": ["vpc_flow_logs_enabled"],
    "encryption": [
        "ec2_ebs_default_encryption",
        "rds_instance_storage_encrypted",
        "s3_bucket_default_encryption",
    ],
}

# Severity mapping from Prowler to CloudSecure
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Run Prowler security scan.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - roleArn: ARN of the IAM role to assume
            - externalId: External ID for role assumption
            - regions: List of regions to scan (optional, defaults to all)

    Returns:
        dict with scan results and findings
    """
    logger.info(f"Starting Prowler scan for assessment: {event.get('assessmentId')}")

    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    role_arn = event.get("roleArn")
    external_id = event.get("externalId")
    regions = event.get("regions", [])
    scope = event.get("scope", ["all"])

    if not all([assessment_id, account_id, role_arn, external_id]):
        return {
            "success": False,
            "analyzer": "prowler",
            "error": "Missing required parameters",
            "assessmentId": assessment_id,
        }

    # Resolve checks based on scope
    if "all" in scope:
        checks = ALL_CHECKS
    else:
        checks = []
        for s in scope:
            checks.extend(SCOPE_CHECKS.get(s, []))
        checks = list(dict.fromkeys(checks))  # deduplicate preserving order

    if not checks:
        logger.info(f"No Prowler checks match scope {scope} — skipping")
        return {
            "success": True,
            "analyzer": "prowler",
            "assessmentId": assessment_id,
            "findingsCount": 0,
            "findings": [],
            "skipped": True,
        }

    logger.info(f"Prowler scope={scope}, running {len(checks)} checks")

    try:
        # Update assessment progress
        update_assessment_progress(assessment_id, 50)

        # Get temporary credentials for the target account
        credentials = assume_role(role_arn, external_id, assessment_id)

        # Run Prowler
        with tempfile.TemporaryDirectory() as output_dir:
            prowler_output = run_prowler(
                credentials=credentials,
                account_id=account_id,
                output_dir=output_dir,
                regions=regions[:5] if regions else None,
                checks=checks,
            )

            if not prowler_output["success"]:
                return {
                    "success": False,
                    "analyzer": "prowler",
                    "assessmentId": assessment_id,
                    "error": prowler_output.get("error", "Prowler execution failed"),
                }

            # Parse and normalize findings
            findings = parse_prowler_output(
                output_dir=output_dir,
                assessment_id=assessment_id,
                account_id=account_id,
            )

            logger.info(f"Prowler scan complete. Found {len(findings)} findings")

            # Calculate severity summary
            summary = {
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in findings if f["severity"] == "LOW"),
                "info": sum(1 for f in findings if f["severity"] == "INFO"),
            }

            return {
                "success": True,
                "analyzer": "prowler",
                "assessmentId": assessment_id,
                "findingsCount": len(findings),
                "findings": findings,
                "summary": summary,
                "prowlerVersion": prowler_output.get("version", "unknown"),
                "compliance": PROWLER_COMPLIANCE_FRAMEWORK,
            }

    except Exception as e:
        logger.exception(f"Prowler scan failed: {e}")
        return {
            "success": False,
            "analyzer": "prowler",
            "assessmentId": assessment_id,
            "error": str(e),
        }


def assume_role(role_arn: str, external_id: str, assessment_id: str) -> dict[str, str]:
    """Assume cross-account role and return credentials.

    Args:
        role_arn: ARN of role to assume
        external_id: External ID for assume role
        assessment_id: Assessment ID for session name

    Returns:
        dict with AccessKeyId, SecretAccessKey, SessionToken
    """
    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"CloudSecure-Prowler-{assessment_id[:8]}",
        ExternalId=external_id,
        DurationSeconds=3600,
    )

    return {
        "AccessKeyId": response["Credentials"]["AccessKeyId"],
        "SecretAccessKey": response["Credentials"]["SecretAccessKey"],
        "SessionToken": response["Credentials"]["SessionToken"],
    }


def run_prowler(
    credentials: dict[str, str],
    account_id: str,
    output_dir: str,
    regions: list[str] | None = None,
    checks: list[str] | None = None,
) -> dict[str, Any]:
    """Execute Prowler CLI.

    Args:
        credentials: AWS credentials dict
        account_id: Target AWS account ID
        output_dir: Directory for output files
        regions: Optional list of regions to scan
        checks: List of Prowler check IDs to run (defaults to ALL_CHECKS)

    Returns:
        dict with success status and version
    """
    checks = checks or ALL_CHECKS
    logger.info(f"Running Prowler for account {account_id} with {len(checks)} checks")

    # Set environment variables for AWS credentials
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = credentials["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = credentials["SecretAccessKey"]
    env["AWS_SESSION_TOKEN"] = credentials["SessionToken"]
    env["AWS_DEFAULT_REGION"] = "us-east-1"

    # Build Prowler command
    # Note: Prowler 5.x uses json-ocsf format and --compliance and --checks are mutually exclusive
    cmd = [
        "prowler",
        "aws",
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        output_dir,
        "--no-banner",
        "--ignore-exit-code-3",  # Don't fail on findings
    ]

    # Add region filter if specified
    # Prowler 5.x expects regions as separate arguments (not comma-separated)
    if regions:
        cmd.append("--filter-region")
        cmd.extend(regions)

    # Prowler 5.x expects checks as separate arguments (not comma-separated)
    cmd.append("--checks")
    cmd.extend(checks)

    logger.info(f"Prowler command: {' '.join(cmd[:10])}...")  # Log partial command

    try:
        # Run Prowler with timeout
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=PROWLER_TIMEOUT_SECONDS,
        )

        logger.info(f"Prowler exit code: {result.returncode}")

        if result.returncode not in [0, 3]:  # 0=success, 3=findings found
            logger.error(f"Prowler stderr: {result.stderr[:1000]}")
            return {
                "success": False,
                "error": f"Prowler failed with exit code {result.returncode}",
            }

        # Get Prowler version from output
        version = "unknown"
        if "Prowler" in result.stdout:
            # Try to extract version
            for line in result.stdout.split("\n"):
                if "version" in line.lower():
                    version = line.strip()
                    break

        return {
            "success": True,
            "version": version,
        }

    except subprocess.TimeoutExpired:
        logger.error("Prowler timed out")
        return {
            "success": False,
            "error": f"Prowler timed out after {PROWLER_TIMEOUT_SECONDS} seconds",
        }

    except Exception as e:
        logger.exception(f"Error running Prowler: {e}")
        return {
            "success": False,
            "error": str(e),
        }


def parse_prowler_output(
    output_dir: str,
    assessment_id: str,
    account_id: str,
) -> list[dict[str, Any]]:
    """Parse Prowler JSON output and normalize to CloudSecure format.

    Args:
        output_dir: Directory containing Prowler output
        assessment_id: Assessment ID
        account_id: AWS account ID

    Returns:
        List of normalized findings
    """
    findings = []

    # Find JSON output file
    output_path = Path(output_dir)
    json_files = list(output_path.glob("**/*.json"))

    if not json_files:
        logger.warning("No Prowler JSON output found")
        return findings

    for json_file in json_files:
        logger.info(f"Parsing Prowler output: {json_file}")

        try:
            with open(json_file) as f:
                content = f.read().strip()

            if not content:
                continue

            # Try parsing as JSON array first (Prowler 5.x OCSF format)
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    # JSON array format
                    for prowler_finding in data:
                        if isinstance(prowler_finding, dict):
                            normalized = normalize_prowler_finding(
                                prowler_finding,
                                assessment_id,
                                account_id,
                            )
                            if normalized:
                                findings.append(normalized)
                elif isinstance(data, dict):
                    # Single finding as JSON object
                    normalized = normalize_prowler_finding(
                        data,
                        assessment_id,
                        account_id,
                    )
                    if normalized:
                        findings.append(normalized)
            except json.JSONDecodeError:
                # Fall back to JSON lines format (legacy Prowler)
                for line in content.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        prowler_finding = json.loads(line)
                        if isinstance(prowler_finding, dict):
                            normalized = normalize_prowler_finding(
                                prowler_finding,
                                assessment_id,
                                account_id,
                            )
                            if normalized:
                                findings.append(normalized)
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.error(f"Error parsing {json_file}: {e}")

    return findings


def normalize_prowler_finding(
    prowler_finding: dict[str, Any],
    assessment_id: str,
    account_id: str,
) -> dict[str, Any] | None:
    """Normalize a single Prowler finding to CloudSecure format.

    Handles both legacy Prowler JSON format and OCSF (json-ocsf) format.

    Args:
        prowler_finding: Raw Prowler finding
        assessment_id: Assessment ID
        account_id: AWS account ID

    Returns:
        Normalized finding dict or None if should be skipped
    """
    # Detect OCSF format vs legacy format
    # OCSF uses 'status_id' and 'severity_id' instead of 'Status' and 'Severity'
    is_ocsf = "status_id" in prowler_finding or "finding_info" in prowler_finding

    if is_ocsf:
        return normalize_ocsf_finding(prowler_finding, assessment_id, account_id)
    else:
        return normalize_legacy_finding(prowler_finding, assessment_id, account_id)


def normalize_ocsf_finding(
    prowler_finding: dict[str, Any],
    assessment_id: str,
    account_id: str,
) -> dict[str, Any] | None:
    """Normalize OCSF format Prowler finding."""
    # OCSF status_id: 1=New, 2=In Progress, 99=Other
    # We extract status from finding_info or status field
    finding_info = prowler_finding.get("finding_info", {})
    status = prowler_finding.get("status", "").upper()

    # Skip PASS findings - OCSF uses different status representation
    # Check both the status and status_id fields
    if status in ["PASS", "PASSED"] or prowler_finding.get("status_id") == 1:
        # status_id=1 typically means "pass" in Prowler OCSF
        pass_statuses = ["pass", "passed", "info", "manual"]
        if status.lower() in pass_statuses:
            return None

    # Map OCSF severity: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
    severity_id = prowler_finding.get("severity_id", 3)
    severity_map = {0: "INFO", 1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
    severity = severity_map.get(severity_id, "MEDIUM")

    # Extract resource from OCSF resources array
    resources = prowler_finding.get("resources", [])
    resource_info = resources[0] if resources else {}

    resource_id = resource_info.get("uid", "unknown")
    resource_arn = resource_info.get("cloud", {}).get("account", {}).get("uid", "")
    resource_type = resource_info.get("type", "unknown")
    region = resource_info.get("region", "global")

    # OCSF compliance information
    compliance_mappings = []
    compliance_info = prowler_finding.get("compliance", {})
    if isinstance(compliance_info, dict):
        for framework, controls in compliance_info.items():
            if isinstance(controls, list):
                for control in controls:
                    compliance_mappings.append({"framework": framework, "control": control})

    # Extract check info
    check_id = finding_info.get("uid", prowler_finding.get("metadata", {}).get("event_code", ""))
    title = finding_info.get("title", prowler_finding.get("message", "Unknown Check"))
    description = prowler_finding.get("message", finding_info.get("desc", ""))

    # Extract remediation
    remediation_info = prowler_finding.get("remediation", {})
    remediation_desc = remediation_info.get("desc", "")
    remediation_url = ""
    if isinstance(remediation_info.get("references"), list) and remediation_info["references"]:
        remediation_url = remediation_info["references"][0]

    return {
        "findingId": str(uuid4()),
        "assessmentId": assessment_id,
        "source": "prowler",
        "sourceId": check_id,
        "severity": severity,
        "title": title,
        "description": description,
        "resourceType": map_resource_type(resource_type),
        "resourceId": resource_id,
        "resourceArn": resource_arn if resource_arn else None,
        "region": region,
        "accountId": account_id,
        "complianceFrameworks": compliance_mappings,
        "remediation": {
            "description": remediation_desc,
            "url": remediation_url,
        },
        "metadata": {
            "checkId": check_id,
            "serviceName": prowler_finding.get("metadata", {})
            .get("product", {})
            .get("feature", {})
            .get("name", ""),
            "subServiceName": "",
            "prowlerStatus": status,
        },
    }


def normalize_legacy_finding(
    prowler_finding: dict[str, Any],
    assessment_id: str,
    account_id: str,
) -> dict[str, Any] | None:
    """Normalize legacy Prowler JSON format finding."""
    # Skip PASS findings - we only want failures
    status = prowler_finding.get("Status", "").upper()
    if status in ["PASS", "INFO", "MANUAL"]:
        return None

    # Map severity
    prowler_severity = prowler_finding.get("Severity", "medium").lower()
    severity = SEVERITY_MAP.get(prowler_severity, "MEDIUM")

    # Extract resource information
    resource_id = prowler_finding.get("ResourceId", "unknown")
    resource_arn = prowler_finding.get("ResourceArn", "")
    resource_type = prowler_finding.get("ResourceType", "unknown")
    region = prowler_finding.get("Region", "global")

    # Build compliance mapping
    compliance_mappings = []
    compliance_info = prowler_finding.get("Compliance", {})

    if isinstance(compliance_info, dict):
        for framework, controls in compliance_info.items():
            if isinstance(controls, list):
                for control in controls:
                    compliance_mappings.append(
                        {
                            "framework": framework,
                            "control": control,
                        }
                    )

    # Create normalized finding
    return {
        "findingId": str(uuid4()),
        "assessmentId": assessment_id,
        "source": "prowler",
        "sourceId": prowler_finding.get("CheckID", ""),
        "severity": severity,
        "title": prowler_finding.get("CheckTitle", "Unknown Check"),
        "description": prowler_finding.get(
            "StatusExtended", prowler_finding.get("Description", "")
        ),
        "resourceType": map_resource_type(resource_type),
        "resourceId": resource_id,
        "resourceArn": resource_arn if resource_arn else None,
        "region": region,
        "accountId": account_id,
        "complianceFrameworks": compliance_mappings,
        "remediation": {
            "description": prowler_finding.get("Remediation", {})
            .get("Recommendation", {})
            .get("Text", ""),
            "url": prowler_finding.get("Remediation", {}).get("Recommendation", {}).get("Url", ""),
        },
        "metadata": {
            "checkId": prowler_finding.get("CheckID", ""),
            "serviceName": prowler_finding.get("ServiceName", ""),
            "subServiceName": prowler_finding.get("SubServiceName", ""),
            "prowlerStatus": status,
        },
    }


def map_resource_type(prowler_type: str) -> str:
    """Map Prowler resource type to AWS CloudFormation format.

    Args:
        prowler_type: Prowler resource type string

    Returns:
        AWS CloudFormation resource type
    """
    type_map = {
        "AwsAccount": "AWS::Account",
        "AwsIamUser": "AWS::IAM::User",
        "AwsIamRole": "AWS::IAM::Role",
        "AwsIamPolicy": "AWS::IAM::Policy",
        "AwsS3Bucket": "AWS::S3::Bucket",
        "AwsEc2SecurityGroup": "AWS::EC2::SecurityGroup",
        "AwsEc2Instance": "AWS::EC2::Instance",
        "AwsEc2Vpc": "AWS::EC2::VPC",
        "AwsEc2Volume": "AWS::EC2::Volume",
        "AwsRdsDbInstance": "AWS::RDS::DBInstance",
        "AwsCloudTrailTrail": "AWS::CloudTrail::Trail",
        "AwsKmsKey": "AWS::KMS::Key",
    }

    return type_map.get(prowler_type, f"AWS::{prowler_type}")


def update_assessment_progress(assessment_id: str, progress: int) -> None:
    """Update assessment progress in DynamoDB.

    Args:
        assessment_id: Assessment ID
        progress: Progress percentage
    """
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression="SET progress = :progress, updatedAt = :updatedAt",
            ExpressionAttributeValues={
                ":progress": progress,
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Failed to update progress: {e}")
