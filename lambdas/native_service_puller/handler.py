"""Native Service Puller Lambda - Pulls findings from AWS native security services.

This Lambda:
1. Pulls findings from SecurityHub (if enabled)
2. Pulls findings from GuardDuty (if enabled)
3. Pulls compliance results from AWS Config (if enabled)
4. Normalizes findings to CloudSecure format
5. Handles gracefully when services are not enabled
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsecure-findings-dev")

# Severity mapping
SECURITYHUB_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "INFO",
}

GUARDDUTY_SEVERITY_MAP = {
    # GuardDuty uses numeric severity 0-10
    # 7.0-8.9 = High, 4.0-6.9 = Medium, 0.1-3.9 = Low
}

CONFIG_COMPLIANCE_MAP = {
    "NON_COMPLIANT": "HIGH",
    "COMPLIANT": "INFO",
    "NOT_APPLICABLE": "INFO",
    "INSUFFICIENT_DATA": "LOW",
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Pull findings from AWS native security services.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - roleArn: ARN of the IAM role to assume
            - externalId: External ID for role assumption
            - regions: List of regions to check

    Returns:
        dict with findings from native services
    """
    logger.info(f"Starting native service pull for assessment: {event.get('assessmentId')}")

    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    role_arn = event.get("roleArn")
    external_id = event.get("externalId")
    regions = event.get("regions", ["us-east-1"])

    if not all([assessment_id, account_id, role_arn, external_id]):
        return {
            "success": False,
            "analyzer": "native-services",
            "error": "Missing required parameters",
            "assessmentId": assessment_id,
        }

    try:
        # Assume cross-account role
        credentials = assume_role(role_arn, external_id, assessment_id)

        all_findings = []
        service_status = {}

        # Pull from each service
        for region in regions[:5]:  # Limit regions for speed
            # SecurityHub
            securityhub_result = pull_securityhub_findings(credentials, region)
            service_status[f"securityhub-{region}"] = securityhub_result["status"]
            all_findings.extend(securityhub_result.get("findings", []))

            # GuardDuty
            guardduty_result = pull_guardduty_findings(credentials, region)
            service_status[f"guardduty-{region}"] = guardduty_result["status"]
            all_findings.extend(guardduty_result.get("findings", []))

            # AWS Config
            config_result = pull_config_compliance(credentials, region)
            service_status[f"config-{region}"] = config_result["status"]
            all_findings.extend(config_result.get("findings", []))

        # Normalize findings
        normalized_findings = []
        for finding in all_findings:
            normalized = normalize_finding(finding, assessment_id, account_id)
            if normalized:
                normalized_findings.append(normalized)

        logger.info(f"Pulled {len(normalized_findings)} findings from native services")

        # Store findings in DynamoDB instead of returning them
        # This avoids Step Functions 256KB limit
        store_findings_in_dynamodb(normalized_findings)

        # Calculate summary
        summary = {
            "critical": sum(1 for f in normalized_findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in normalized_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in normalized_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in normalized_findings if f["severity"] == "LOW"),
            "info": sum(1 for f in normalized_findings if f["severity"] == "INFO"),
        }

        return {
            "success": True,
            "analyzer": "native-services",
            "assessmentId": assessment_id,
            "findingsCount": len(normalized_findings),
            # Don't return findings inline - they're stored in DynamoDB
            "summary": summary,
            "serviceStatus": service_status,
        }

    except Exception as e:
        logger.exception(f"Native service pull failed: {e}")
        return {
            "success": False,
            "analyzer": "native-services",
            "assessmentId": assessment_id,
            "error": str(e),
        }


def store_findings_in_dynamodb(findings: list[dict[str, Any]]) -> None:
    """Store findings in DynamoDB in batches.

    Args:
        findings: List of normalized findings to store
    """
    if not findings:
        return

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(FINDINGS_TABLE)

    # Batch write (max 25 items per batch)
    with table.batch_writer() as batch:
        for finding in findings:
            # Ensure required fields exist
            item = {
                "assessmentId": finding["assessmentId"],
                "findingId": finding["findingId"],
                "source": finding.get("source", "native-services"),
                "severity": finding.get("severity", "INFO"),
                "title": finding.get("title", "Unknown"),
                "description": finding.get("description", ""),
                "resourceType": finding.get("resourceType", "Unknown"),
                "resourceId": finding.get("resourceId", "unknown"),
                "region": finding.get("region", "global"),
                "accountId": finding.get("accountId", ""),
                "createdAt": datetime.utcnow().isoformat(),
            }

            # Add optional fields if present
            if finding.get("resourceArn"):
                item["resourceArn"] = finding["resourceArn"]
            if finding.get("remediation"):
                item["remediation"] = finding["remediation"]
            if finding.get("metadata"):
                item["metadata"] = finding["metadata"]
            if finding.get("sourceId"):
                item["sourceId"] = finding["sourceId"]

            batch.put_item(Item=item)

    logger.info(f"Stored {len(findings)} findings in DynamoDB")


def assume_role(role_arn: str, external_id: str, assessment_id: str) -> dict[str, str]:
    """Assume cross-account role and return credentials."""
    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"CloudSecure-NativeServices-{assessment_id[:8]}",
        ExternalId=external_id,
        DurationSeconds=3600,
    )

    return {
        "AccessKeyId": response["Credentials"]["AccessKeyId"],
        "SecretAccessKey": response["Credentials"]["SecretAccessKey"],
        "SessionToken": response["Credentials"]["SessionToken"],
    }


def get_client(service: str, credentials: dict[str, str], region: str) -> Any:
    """Create a boto3 client with assumed credentials."""
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def pull_securityhub_findings(credentials: dict[str, str], region: str) -> dict[str, Any]:
    """Pull findings from AWS SecurityHub.

    Args:
        credentials: AWS credentials
        region: AWS region

    Returns:
        dict with status and findings
    """
    try:
        client = get_client("securityhub", credentials, region)

        # Check if SecurityHub is enabled
        try:
            client.get_enabled_standards()
        except ClientError as e:
            if "not subscribed" in str(e).lower() or "InvalidAccessException" in str(e):
                logger.info(f"SecurityHub not enabled in {region}")
                return {"status": "not_enabled", "findings": []}
            raise

        # Get findings from the last 30 days
        findings = []
        paginator = client.get_paginator("get_findings")

        filters = {
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "UpdatedAt": [
                {
                    "Start": (datetime.utcnow() - timedelta(days=30)).isoformat() + "Z",
                    "End": datetime.utcnow().isoformat() + "Z",
                }
            ],
        }

        for page in paginator.paginate(Filters=filters, MaxResults=100):
            for finding in page.get("Findings", []):
                findings.append(
                    {
                        "source": "securityhub",
                        "region": region,
                        "raw": finding,
                    }
                )

        logger.info(f"SecurityHub {region}: {len(findings)} findings")
        return {"status": "enabled", "findings": findings}

    except ClientError as e:
        logger.warning(f"SecurityHub error in {region}: {e}")
        return {"status": "error", "error": str(e), "findings": []}


def pull_guardduty_findings(credentials: dict[str, str], region: str) -> dict[str, Any]:
    """Pull findings from AWS GuardDuty.

    Args:
        credentials: AWS credentials
        region: AWS region

    Returns:
        dict with status and findings
    """
    try:
        client = get_client("guardduty", credentials, region)

        # List detectors
        detectors = client.list_detectors()
        if not detectors.get("DetectorIds"):
            logger.info(f"GuardDuty not enabled in {region}")
            return {"status": "not_enabled", "findings": []}

        detector_id = detectors["DetectorIds"][0]

        # Get findings
        findings = []
        finding_criteria = {
            "Criterion": {
                "service.archived": {
                    "Eq": ["false"],
                },
                "updatedAt": {
                    "GreaterThanOrEqual": int(
                        (datetime.utcnow() - timedelta(days=30)).timestamp() * 1000
                    ),
                },
            },
        }

        # List finding IDs
        paginator = client.get_paginator("list_findings")
        finding_ids = []

        for page in paginator.paginate(DetectorId=detector_id, FindingCriteria=finding_criteria):
            finding_ids.extend(page.get("FindingIds", []))

        # Get finding details in batches
        for i in range(0, len(finding_ids), 50):
            batch = finding_ids[i : i + 50]
            if batch:
                response = client.get_findings(DetectorId=detector_id, FindingIds=batch)
                for finding in response.get("Findings", []):
                    findings.append(
                        {
                            "source": "guardduty",
                            "region": region,
                            "raw": finding,
                        }
                    )

        logger.info(f"GuardDuty {region}: {len(findings)} findings")
        return {"status": "enabled", "findings": findings}

    except ClientError as e:
        logger.warning(f"GuardDuty error in {region}: {e}")
        return {"status": "error", "error": str(e), "findings": []}


def pull_config_compliance(credentials: dict[str, str], region: str) -> dict[str, Any]:
    """Pull compliance results from AWS Config.

    Args:
        credentials: AWS credentials
        region: AWS region

    Returns:
        dict with status and findings
    """
    try:
        client = get_client("config", credentials, region)

        # Check if Config is enabled
        try:
            recorders = client.describe_configuration_recorders()
            if not recorders.get("ConfigurationRecorders"):
                logger.info(f"AWS Config not enabled in {region}")
                return {"status": "not_enabled", "findings": []}
        except ClientError:
            return {"status": "not_enabled", "findings": []}

        # Get non-compliant rules
        findings = []
        paginator = client.get_paginator("describe_compliance_by_config_rule")

        for page in paginator.paginate():
            for rule in page.get("ComplianceByConfigRules", []):
                if rule.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT":
                    # Get rule details
                    rule_name = rule.get("ConfigRuleName")
                    try:
                        rule_detail = client.describe_config_rules(ConfigRuleNames=[rule_name])
                        rule_info = rule_detail.get("ConfigRules", [{}])[0]

                        # Get non-compliant resources
                        resources = client.get_compliance_details_by_config_rule(
                            ConfigRuleName=rule_name,
                            ComplianceTypes=["NON_COMPLIANT"],
                            Limit=25,
                        )

                        for result in resources.get("EvaluationResults", []):
                            findings.append(
                                {
                                    "source": "config",
                                    "region": region,
                                    "raw": {
                                        "rule": rule_info,
                                        "evaluation": result,
                                    },
                                }
                            )

                    except ClientError as e:
                        logger.warning(f"Error getting Config rule details: {e}")

        logger.info(f"AWS Config {region}: {len(findings)} findings")
        return {"status": "enabled", "findings": findings}

    except ClientError as e:
        logger.warning(f"AWS Config error in {region}: {e}")
        return {"status": "error", "error": str(e), "findings": []}


def normalize_finding(
    finding: dict[str, Any], assessment_id: str, account_id: str
) -> dict[str, Any] | None:
    """Normalize a finding to CloudSecure format.

    Args:
        finding: Raw finding with source info
        assessment_id: Assessment ID
        account_id: AWS account ID

    Returns:
        Normalized finding dict or None
    """
    source = finding.get("source")
    region = finding.get("region", "global")
    raw = finding.get("raw", {})

    if source == "securityhub":
        return normalize_securityhub_finding(raw, assessment_id, account_id, region)
    elif source == "guardduty":
        return normalize_guardduty_finding(raw, assessment_id, account_id, region)
    elif source == "config":
        return normalize_config_finding(raw, assessment_id, account_id, region)

    return None


def normalize_securityhub_finding(
    raw: dict[str, Any],
    assessment_id: str,
    account_id: str,
    region: str,
) -> dict[str, Any]:
    """Normalize SecurityHub finding."""
    severity_label = raw.get("Severity", {}).get("Label", "INFORMATIONAL")
    severity = SECURITYHUB_SEVERITY_MAP.get(severity_label, "INFO")

    resources = raw.get("Resources", [{}])
    resource = resources[0] if resources else {}

    return {
        "findingId": str(uuid4()),
        "assessmentId": assessment_id,
        "source": "securityhub",
        "sourceId": raw.get("Id", ""),
        "severity": severity,
        "title": raw.get("Title", "Unknown Finding"),
        "description": raw.get("Description", ""),
        "resourceType": resource.get("Type", "Unknown"),
        "resourceId": resource.get("Id", "unknown"),
        "resourceArn": resource.get("Id") if resource.get("Id", "").startswith("arn:") else None,
        "region": region,
        "accountId": account_id,
        "remediation": {
            "description": raw.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
            "url": raw.get("Remediation", {}).get("Recommendation", {}).get("Url", ""),
        },
        "metadata": {
            "productName": raw.get("ProductName", ""),
            "generatorId": raw.get("GeneratorId", ""),
            "workflowStatus": raw.get("Workflow", {}).get("Status", ""),
        },
    }


def normalize_guardduty_finding(
    raw: dict[str, Any],
    assessment_id: str,
    account_id: str,
    region: str,
) -> dict[str, Any]:
    """Normalize GuardDuty finding."""
    # Map numeric severity to category
    severity_num = raw.get("Severity", 0)
    if severity_num >= 7.0:
        severity = "HIGH"
    elif severity_num >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Extract resource info
    resource = raw.get("Resource", {})
    resource_type = resource.get("ResourceType", "Unknown")

    # Get resource ID based on type
    resource_id = "unknown"
    if resource_type == "Instance":
        resource_id = resource.get("InstanceDetails", {}).get("InstanceId", "unknown")
    elif resource_type == "AccessKey":
        resource_id = resource.get("AccessKeyDetails", {}).get("AccessKeyId", "unknown")
    elif resource_type == "S3Bucket":
        resource_id = resource.get("S3BucketDetails", [{}])[0].get("Name", "unknown")

    return {
        "findingId": str(uuid4()),
        "assessmentId": assessment_id,
        "source": "guardduty",
        "sourceId": raw.get("Id", ""),
        "severity": severity,
        "title": raw.get("Title", "Unknown Finding"),
        "description": raw.get("Description", ""),
        "resourceType": f"AWS::{resource_type}",
        "resourceId": resource_id,
        "resourceArn": raw.get("Arn"),
        "region": region,
        "accountId": account_id,
        "remediation": {
            "description": f"Investigate this {raw.get('Type', 'threat')} finding and take appropriate action.",
            "url": "",
        },
        "metadata": {
            "findingType": raw.get("Type", ""),
            "severityScore": severity_num,
            "confidence": raw.get("Confidence", 0),
            "service": raw.get("Service", {}).get("ServiceName", ""),
        },
    }


def normalize_config_finding(
    raw: dict[str, Any],
    assessment_id: str,
    account_id: str,
    region: str,
) -> dict[str, Any]:
    """Normalize AWS Config finding."""
    rule = raw.get("rule", {})
    evaluation = raw.get("evaluation", {})

    resource_id = (
        evaluation.get("EvaluationResultIdentifier", {})
        .get("EvaluationResultQualifier", {})
        .get("ResourceId", "unknown")
    )

    resource_type = (
        evaluation.get("EvaluationResultIdentifier", {})
        .get("EvaluationResultQualifier", {})
        .get("ResourceType", "Unknown")
    )

    compliance_type = evaluation.get("ComplianceType", "NON_COMPLIANT")
    severity = CONFIG_COMPLIANCE_MAP.get(compliance_type, "MEDIUM")

    return {
        "findingId": str(uuid4()),
        "assessmentId": assessment_id,
        "source": "config",
        "sourceId": rule.get("ConfigRuleArn", ""),
        "severity": severity,
        "title": f"Non-compliant: {rule.get('ConfigRuleName', 'Unknown Rule')}",
        "description": rule.get("Description", ""),
        "resourceType": resource_type,
        "resourceId": resource_id,
        "resourceArn": None,
        "region": region,
        "accountId": account_id,
        "remediation": {
            "description": rule.get("InputParameters", ""),
            "url": "",
        },
        "metadata": {
            "configRuleName": rule.get("ConfigRuleName", ""),
            "complianceType": compliance_type,
            "configRuleId": rule.get("ConfigRuleId", ""),
        },
    }
