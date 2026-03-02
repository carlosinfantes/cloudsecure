"""Lambda handler for discovering AWS resources and security service status.

This Lambda discovers:
1. AWS resources across all enabled regions (EC2, S3, RDS, Lambda, etc.)
2. Security service status (SecurityHub, GuardDuty, Config, CloudTrail)
3. Returns discovery summary and identified gaps
"""

import logging
import os

# Add shared module to path
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.aws_client import get_assumed_role_session
from shared.models import AssessmentStatus

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")

# Maximum concurrent region scans
MAX_WORKERS = 10


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Discover AWS resources and security service status.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - roleArn: ARN of the IAM role to assume
            - externalId: External ID for role assumption
            - regions: List of enabled regions from validation step

    Returns:
        dict with discovery results:
            - resources: dict of resource counts by type
            - securityServices: dict of service status
            - gaps: list of identified security gaps
    """
    logger.info(f"Starting discovery for assessment: {event.get('assessmentId')}")

    # Extract parameters
    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    role_arn = event.get("roleArn")
    external_id = event.get("externalId")
    regions = event.get("regions", [])

    if not all([assessment_id, account_id, role_arn, external_id]):
        return {
            "success": False,
            "error": "Missing required parameters",
            "assessmentId": assessment_id,
        }

    # Update assessment progress
    update_assessment_status(assessment_id, AssessmentStatus.RUNNING, progress=15)

    try:
        # Get assumed role session
        session = get_assumed_role_session(
            role_arn=role_arn,
            external_id=external_id,
            session_name=f"CloudSecure-Discovery-{assessment_id[:8]}",
            duration_seconds=3600,
        )

        # Discover security services status (global + regional)
        logger.info("Discovering security services status...")
        security_services = discover_security_services(session, regions)
        update_assessment_status(assessment_id, AssessmentStatus.RUNNING, progress=25)

        # Discover resources across regions
        logger.info(f"Discovering resources across {len(regions)} regions...")
        resources = discover_resources(session, regions)
        update_assessment_status(assessment_id, AssessmentStatus.RUNNING, progress=40)

        # Identify security gaps
        gaps = identify_security_gaps(security_services, resources)

        logger.info(
            f"Discovery complete. Found {sum(resources.get('totals', {}).values())} resources"
        )

        return {
            "success": True,
            "assessmentId": assessment_id,
            "accountId": account_id,
            "roleArn": role_arn,
            "externalId": external_id,
            "regions": regions,
            "resources": resources,
            "securityServices": security_services,
            "gaps": gaps,
            "discoveredAt": datetime.utcnow().isoformat(),
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS API error during discovery: {error_code} - {error_message}")

        update_assessment_status(
            assessment_id,
            AssessmentStatus.FAILED,
            error_message=f"Discovery failed: {error_message}",
        )

        return {
            "success": False,
            "error": f"AWS API error: {error_code} - {error_message}",
            "assessmentId": assessment_id,
        }

    except Exception as e:
        logger.exception(f"Unexpected error during discovery: {e}")

        update_assessment_status(
            assessment_id,
            AssessmentStatus.FAILED,
            error_message=str(e),
        )

        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "assessmentId": assessment_id,
        }


def discover_security_services(session: boto3.Session, regions: list[str]) -> dict[str, Any]:
    """Discover status of AWS security services.

    Args:
        session: boto3 Session with assumed role credentials
        regions: List of regions to check

    Returns:
        dict with security service status
    """
    services = {
        "cloudtrail": {"enabled": False, "trails": []},
        "guardduty": {"enabled": False, "detectors": []},
        "securityhub": {"enabled": False, "standards": []},
        "config": {"enabled": False, "recorders": []},
        "inspector": {"enabled": False},
        "macie": {"enabled": False},
    }

    # Check CloudTrail (global service, check in us-east-1)
    try:
        cloudtrail = session.client("cloudtrail", region_name="us-east-1")
        trails = cloudtrail.describe_trails()["trailList"]
        services["cloudtrail"]["enabled"] = len(trails) > 0
        services["cloudtrail"]["trails"] = [
            {
                "name": t["Name"],
                "isMultiRegion": t.get("IsMultiRegionTrail", False),
                "isOrganizationTrail": t.get("IsOrganizationTrail", False),
                "hasLogFileValidation": t.get("LogFileValidationEnabled", False),
            }
            for t in trails
        ]
    except ClientError as e:
        logger.warning(f"Could not check CloudTrail: {e}")

    # Check GuardDuty across regions
    guardduty_regions = []
    for region in regions[:5]:  # Check first 5 regions for speed
        try:
            gd = session.client("guardduty", region_name=region)
            detectors = gd.list_detectors()["DetectorIds"]
            if detectors:
                guardduty_regions.append(region)
                services["guardduty"]["detectors"].extend(detectors)
        except ClientError:
            pass

    services["guardduty"]["enabled"] = len(guardduty_regions) > 0
    services["guardduty"]["enabledRegions"] = guardduty_regions

    # Check Security Hub across regions
    securityhub_regions = []
    for region in regions[:5]:
        try:
            sh = session.client("securityhub", region_name=region)
            sh.get_enabled_standards()
            securityhub_regions.append(region)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidAccessException":
                pass

    services["securityhub"]["enabled"] = len(securityhub_regions) > 0
    services["securityhub"]["enabledRegions"] = securityhub_regions

    # Check AWS Config across regions
    config_regions = []
    for region in regions[:5]:
        try:
            config = session.client("config", region_name=region)
            recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
            if recorders:
                config_regions.append(region)
                services["config"]["recorders"].extend([r["name"] for r in recorders])
        except ClientError:
            pass

    services["config"]["enabled"] = len(config_regions) > 0
    services["config"]["enabledRegions"] = config_regions

    # Check Inspector (v2)
    try:
        inspector = session.client("inspector2", region_name="us-east-1")
        inspector.batch_get_account_status(accountIds=[])
        services["inspector"]["enabled"] = True
    except ClientError:
        services["inspector"]["enabled"] = False

    # Check Macie
    try:
        macie = session.client("macie2", region_name="us-east-1")
        macie.get_macie_session()
        services["macie"]["enabled"] = True
    except ClientError:
        services["macie"]["enabled"] = False

    return services


def discover_resources(session: boto3.Session, regions: list[str]) -> dict[str, Any]:
    """Discover AWS resources across regions.

    Args:
        session: boto3 Session with assumed role credentials
        regions: List of regions to scan

    Returns:
        dict with resource counts by type and region
    """
    resources = {
        "byRegion": {},
        "totals": {
            "ec2_instances": 0,
            "ec2_security_groups": 0,
            "ec2_vpcs": 0,
            "s3_buckets": 0,
            "rds_instances": 0,
            "lambda_functions": 0,
            "iam_users": 0,
            "iam_roles": 0,
        },
    }

    # Discover global resources first
    global_resources = discover_global_resources(session)
    resources["totals"]["s3_buckets"] = global_resources.get("s3_buckets", 0)
    resources["totals"]["iam_users"] = global_resources.get("iam_users", 0)
    resources["totals"]["iam_roles"] = global_resources.get("iam_roles", 0)
    resources["global"] = global_resources

    # Discover regional resources in parallel
    def scan_region(region: str) -> tuple[str, dict]:
        return region, discover_regional_resources(session, region)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_region, region): region for region in regions}

        for future in as_completed(futures):
            try:
                region, region_resources = future.result()
                resources["byRegion"][region] = region_resources

                # Update totals
                for resource_type, count in region_resources.items():
                    if resource_type in resources["totals"]:
                        resources["totals"][resource_type] += count

            except Exception as e:
                region = futures[future]
                logger.error(f"Error scanning region {region}: {e}")
                resources["byRegion"][region] = {"error": str(e)}

    return resources


def discover_global_resources(session: boto3.Session) -> dict[str, int]:
    """Discover global AWS resources (S3, IAM).

    Args:
        session: boto3 Session with assumed role credentials

    Returns:
        dict with global resource counts
    """
    resources = {}

    # S3 buckets (global)
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets()["Buckets"]
        resources["s3_buckets"] = len(buckets)
    except ClientError as e:
        logger.warning(f"Could not list S3 buckets: {e}")
        resources["s3_buckets"] = 0

    # IAM users
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        user_count = 0
        for page in paginator.paginate():
            user_count += len(page["Users"])
        resources["iam_users"] = user_count
    except ClientError as e:
        logger.warning(f"Could not list IAM users: {e}")
        resources["iam_users"] = 0

    # IAM roles
    try:
        iam = session.client("iam")
        paginator = iam.get_paginator("list_roles")
        role_count = 0
        for page in paginator.paginate():
            role_count += len(page["Roles"])
        resources["iam_roles"] = role_count
    except ClientError as e:
        logger.warning(f"Could not list IAM roles: {e}")
        resources["iam_roles"] = 0

    return resources


def discover_regional_resources(session: boto3.Session, region: str) -> dict[str, int]:
    """Discover resources in a specific region.

    Args:
        session: boto3 Session with assumed role credentials
        region: AWS region to scan

    Returns:
        dict with resource counts for the region
    """
    resources = {}

    # EC2 instances
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")
        instance_count = 0
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                instance_count += len(reservation["Instances"])
        resources["ec2_instances"] = instance_count
    except ClientError as e:
        logger.warning(f"Could not list EC2 instances in {region}: {e}")
        resources["ec2_instances"] = 0

    # Security Groups
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        sg_count = 0
        for page in paginator.paginate():
            sg_count += len(page["SecurityGroups"])
        resources["ec2_security_groups"] = sg_count
    except ClientError as e:
        logger.warning(f"Could not list security groups in {region}: {e}")
        resources["ec2_security_groups"] = 0

    # VPCs
    try:
        ec2 = session.client("ec2", region_name=region)
        vpcs = ec2.describe_vpcs()["Vpcs"]
        resources["ec2_vpcs"] = len(vpcs)
    except ClientError as e:
        logger.warning(f"Could not list VPCs in {region}: {e}")
        resources["ec2_vpcs"] = 0

    # RDS instances
    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        rds_count = 0
        for page in paginator.paginate():
            rds_count += len(page["DBInstances"])
        resources["rds_instances"] = rds_count
    except ClientError as e:
        logger.warning(f"Could not list RDS instances in {region}: {e}")
        resources["rds_instances"] = 0

    # Lambda functions
    try:
        lambda_client = session.client("lambda", region_name=region)
        paginator = lambda_client.get_paginator("list_functions")
        lambda_count = 0
        for page in paginator.paginate():
            lambda_count += len(page["Functions"])
        resources["lambda_functions"] = lambda_count
    except ClientError as e:
        logger.warning(f"Could not list Lambda functions in {region}: {e}")
        resources["lambda_functions"] = 0

    return resources


def identify_security_gaps(
    security_services: dict[str, Any],
    resources: dict[str, Any],
) -> list[dict[str, Any]]:
    """Identify security gaps based on discovered services and resources.

    Args:
        security_services: Security service status
        resources: Discovered resources

    Returns:
        List of identified security gaps
    """
    gaps = []

    # Check for missing CloudTrail
    if not security_services.get("cloudtrail", {}).get("enabled"):
        gaps.append(
            {
                "type": "MISSING_SERVICE",
                "service": "CloudTrail",
                "severity": "HIGH",
                "description": "CloudTrail is not enabled. API activity is not being logged.",
                "recommendation": "Enable CloudTrail with multi-region logging and log file validation.",
            }
        )
    else:
        # Check for multi-region trail
        trails = security_services.get("cloudtrail", {}).get("trails", [])
        has_multi_region = any(t.get("isMultiRegion") for t in trails)
        if not has_multi_region:
            gaps.append(
                {
                    "type": "CONFIGURATION_GAP",
                    "service": "CloudTrail",
                    "severity": "MEDIUM",
                    "description": "No multi-region CloudTrail trail configured.",
                    "recommendation": "Configure at least one multi-region trail for comprehensive logging.",
                }
            )

    # Check for missing GuardDuty
    if not security_services.get("guardduty", {}).get("enabled"):
        gaps.append(
            {
                "type": "MISSING_SERVICE",
                "service": "GuardDuty",
                "severity": "HIGH",
                "description": "GuardDuty is not enabled. Threat detection is not active.",
                "recommendation": "Enable GuardDuty in all regions for continuous threat detection.",
            }
        )

    # Check for missing Security Hub
    if not security_services.get("securityhub", {}).get("enabled"):
        gaps.append(
            {
                "type": "MISSING_SERVICE",
                "service": "SecurityHub",
                "severity": "MEDIUM",
                "description": "Security Hub is not enabled. Security findings are not aggregated.",
                "recommendation": "Enable Security Hub to aggregate and prioritize security findings.",
            }
        )

    # Check for missing AWS Config
    if not security_services.get("config", {}).get("enabled"):
        gaps.append(
            {
                "type": "MISSING_SERVICE",
                "service": "AWS Config",
                "severity": "MEDIUM",
                "description": "AWS Config is not enabled. Resource configuration changes are not tracked.",
                "recommendation": "Enable AWS Config to track configuration changes and compliance.",
            }
        )

    # Check for resources without monitoring
    totals = resources.get("totals", {})

    if totals.get("ec2_instances", 0) > 0 and not security_services.get("inspector", {}).get(
        "enabled"
    ):
        gaps.append(
            {
                "type": "COVERAGE_GAP",
                "service": "Inspector",
                "severity": "LOW",
                "description": f"Inspector is not enabled but {totals['ec2_instances']} EC2 instances exist.",
                "recommendation": "Enable Inspector for automated vulnerability scanning of EC2 instances.",
            }
        )

    if totals.get("s3_buckets", 0) > 0 and not security_services.get("macie", {}).get("enabled"):
        gaps.append(
            {
                "type": "COVERAGE_GAP",
                "service": "Macie",
                "severity": "LOW",
                "description": f"Macie is not enabled but {totals['s3_buckets']} S3 buckets exist.",
                "recommendation": "Enable Macie for automated sensitive data discovery in S3 buckets.",
            }
        )

    return gaps


def update_assessment_status(
    assessment_id: str,
    status: AssessmentStatus,
    progress: int | None = None,
    error_message: str | None = None,
) -> None:
    """Update assessment status in DynamoDB.

    Args:
        assessment_id: UUID of the assessment
        status: New status
        progress: Progress percentage (0-100)
        error_message: Error message if failed
    """
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        update_expr = "SET #status = :status, updatedAt = :updatedAt"
        expr_values: dict[str, Any] = {
            ":status": status.value,
            ":updatedAt": datetime.utcnow().isoformat(),
        }
        expr_names = {"#status": "status"}

        if progress is not None:
            update_expr += ", progress = :progress"
            expr_values[":progress"] = progress

        if error_message:
            update_expr += ", errorMessage = :errorMessage"
            expr_values[":errorMessage"] = error_message

        if status == AssessmentStatus.FAILED:
            update_expr += ", completedAt = :completedAt"
            expr_values[":completedAt"] = datetime.utcnow().isoformat()

        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

        logger.info(f"Updated assessment {assessment_id} status to {status.value}")

    except Exception as e:
        logger.error(f"Failed to update assessment status: {e}")
