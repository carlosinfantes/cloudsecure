"""Lambda handler for validating cross-account IAM role permissions.

This Lambda validates that:
1. The provided IAM role can be assumed with the given external ID
2. The role has ReadOnlyAccess and SecurityAudit permissions
3. Returns account information and enabled regions
"""

import logging
import os

# Add shared module to path
import sys
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.aws_client import get_all_regions, get_assumed_role_session
from shared.models import AssessmentStatus

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Validate cross-account IAM role and return validation results.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - roleArn: ARN of the IAM role to assume
            - externalId: External ID for role assumption

    Returns:
        dict with validation results:
            - valid: bool
            - accountId: str
            - regions: list of enabled regions
            - error: str (if invalid)
    """
    logger.info(f"Validating role for assessment: {event.get('assessmentId')}")

    # Extract parameters
    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    role_arn = event.get("roleArn")
    external_id = event.get("externalId")

    # Validate required parameters
    if not all([assessment_id, account_id, role_arn, external_id]):
        return {
            "valid": False,
            "error": "Missing required parameters: assessmentId, accountId, roleArn, externalId",
            "assessmentId": assessment_id,
        }

    # Update assessment status to RUNNING
    update_assessment_status(assessment_id, AssessmentStatus.RUNNING, progress=5)

    try:
        # Attempt to assume the role
        logger.info(f"Attempting to assume role: {role_arn}")
        session = get_assumed_role_session(
            role_arn=role_arn,
            external_id=external_id,
            session_name=f"CloudSecure-{assessment_id[:8]}",
            duration_seconds=3600,
        )

        # Verify we got valid credentials
        sts = session.client("sts")
        caller_identity = sts.get_caller_identity()
        assumed_account = caller_identity["Account"]

        if assumed_account != account_id:
            return {
                "valid": False,
                "error": f"Account mismatch: expected {account_id}, got {assumed_account}",
                "assessmentId": assessment_id,
            }

        # Get list of enabled regions
        regions = get_all_regions(session)
        logger.info(f"Found {len(regions)} enabled regions")

        # Verify basic permissions by making test API calls
        permissions_check = verify_permissions(session)

        if not permissions_check["valid"]:
            update_assessment_status(
                assessment_id,
                AssessmentStatus.FAILED,
                error_message=permissions_check["error"],
            )
            return {
                "valid": False,
                "error": permissions_check["error"],
                "assessmentId": assessment_id,
            }

        # Update assessment progress
        update_assessment_status(assessment_id, AssessmentStatus.RUNNING, progress=10)

        logger.info(f"Role validation successful for account {account_id}")

        return {
            "valid": True,
            "assessmentId": assessment_id,
            "accountId": account_id,
            "roleArn": role_arn,
            "externalId": external_id,
            "regions": regions,
            "scope": event.get("scope", ["all"]),
            "assumedRoleArn": caller_identity["Arn"],
            "permissionsVerified": permissions_check["permissions"],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]

        logger.error(f"Role assumption failed: {error_code} - {error_message}")

        # Update assessment as failed
        update_assessment_status(
            assessment_id,
            AssessmentStatus.FAILED,
            error_message=f"Role assumption failed: {error_message}",
        )

        return {
            "valid": False,
            "error": f"Role assumption failed: {error_code} - {error_message}",
            "assessmentId": assessment_id,
        }

    except Exception as e:
        logger.exception(f"Unexpected error during role validation: {e}")

        update_assessment_status(
            assessment_id,
            AssessmentStatus.FAILED,
            error_message=str(e),
        )

        return {
            "valid": False,
            "error": f"Unexpected error: {str(e)}",
            "assessmentId": assessment_id,
        }


def verify_permissions(session: boto3.Session) -> dict[str, Any]:
    """Verify that the assumed role has required permissions.

    Args:
        session: boto3 Session with assumed role credentials

    Returns:
        dict with verification results
    """
    permissions = {}
    errors = []

    # Test EC2 read access (part of ReadOnlyAccess)
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        ec2.describe_regions(AllRegions=False)
        permissions["ec2:DescribeRegions"] = True
    except ClientError as e:
        permissions["ec2:DescribeRegions"] = False
        errors.append(f"EC2: {e.response['Error']['Message']}")

    # Test IAM read access (part of SecurityAudit)
    try:
        iam = session.client("iam")
        iam.list_users(MaxItems=1)
        permissions["iam:ListUsers"] = True
    except ClientError as e:
        permissions["iam:ListUsers"] = False
        errors.append(f"IAM: {e.response['Error']['Message']}")

    # Test S3 read access
    try:
        s3 = session.client("s3")
        s3.list_buckets()
        permissions["s3:ListBuckets"] = True
    except ClientError as e:
        permissions["s3:ListBuckets"] = False
        errors.append(f"S3: {e.response['Error']['Message']}")

    # Test CloudTrail read access (important for security assessment)
    try:
        cloudtrail = session.client("cloudtrail", region_name="us-east-1")
        cloudtrail.describe_trails()
        permissions["cloudtrail:DescribeTrails"] = True
    except ClientError as e:
        permissions["cloudtrail:DescribeTrails"] = False
        errors.append(f"CloudTrail: {e.response['Error']['Message']}")

    # Determine if we have minimum required permissions
    required_permissions = ["ec2:DescribeRegions", "iam:ListUsers", "s3:ListBuckets"]
    has_required = all(permissions.get(p, False) for p in required_permissions)

    if not has_required:
        return {
            "valid": False,
            "error": f"Missing required permissions: {', '.join(errors)}",
            "permissions": permissions,
        }

    return {
        "valid": True,
        "permissions": permissions,
    }


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

        if status == AssessmentStatus.RUNNING:
            update_expr += ", startedAt = if_not_exists(startedAt, :startedAt)"
            expr_values[":startedAt"] = datetime.utcnow().isoformat()

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
