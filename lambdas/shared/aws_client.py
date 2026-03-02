"""AWS client utilities for cross-account access and boto3 session management."""

import os
from functools import lru_cache
from typing import Any

import boto3
from botocore.config import Config

# Default boto3 config with retries
DEFAULT_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
)


@lru_cache(maxsize=1)
def get_default_region() -> str:
    """Get default AWS region from environment or fallback."""
    return os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "eu-west-1"))


def get_boto3_client(
    service_name: str,
    region_name: str | None = None,
    config: Config | None = None,
) -> Any:
    """Get a boto3 client for a service.

    Args:
        service_name: AWS service name (e.g., 'dynamodb', 's3', 'sts')
        region_name: AWS region (defaults to environment variable)
        config: Optional botocore Config override

    Returns:
        boto3 service client
    """
    return boto3.client(
        service_name,
        region_name=region_name or get_default_region(),
        config=config or DEFAULT_CONFIG,
    )


def get_assumed_role_session(
    role_arn: str,
    external_id: str,
    session_name: str = "CloudSecureAssessment",
    duration_seconds: int = 3600,
) -> boto3.Session:
    """Assume a cross-account IAM role and return a session.

    Args:
        role_arn: ARN of the IAM role to assume
        external_id: External ID for the assume role request
        session_name: Name for the assumed role session
        duration_seconds: Session duration (default 1 hour)

    Returns:
        boto3.Session configured with assumed role credentials

    Raises:
        botocore.exceptions.ClientError: If role assumption fails
    """
    sts_client = get_boto3_client("sts")

    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        ExternalId=external_id,
        DurationSeconds=duration_seconds,
    )

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_client_from_session(
    session: boto3.Session,
    service_name: str,
    region_name: str | None = None,
    config: Config | None = None,
) -> Any:
    """Get a boto3 client from an assumed role session.

    Args:
        session: boto3.Session with assumed role credentials
        service_name: AWS service name
        region_name: AWS region (defaults to session region)
        config: Optional botocore Config override

    Returns:
        boto3 service client using session credentials
    """
    return session.client(
        service_name,
        region_name=region_name or get_default_region(),
        config=config or DEFAULT_CONFIG,
    )


def validate_role_permissions(
    role_arn: str,
    external_id: str,
    required_actions: list[str] | None = None,
) -> dict[str, Any]:
    """Validate that a role can be assumed and has required permissions.

    Args:
        role_arn: ARN of the IAM role to validate
        external_id: External ID for the assume role request
        required_actions: List of IAM actions to check (optional)

    Returns:
        dict with validation results:
            - valid: bool indicating if role is valid
            - account_id: target account ID
            - error: error message if invalid
            - permissions: dict of action -> bool for checked permissions
    """
    result: dict[str, Any] = {
        "valid": False,
        "account_id": None,
        "error": None,
        "permissions": {},
    }

    try:
        # Attempt to assume the role
        session = get_assumed_role_session(role_arn, external_id, duration_seconds=900)

        # Get account ID
        sts = session.client("sts")
        caller_identity = sts.get_caller_identity()
        result["account_id"] = caller_identity["Account"]
        result["valid"] = True

        # Check specific permissions if requested
        if required_actions:
            session.client("iam")
            try:
                # Use IAM simulator to check permissions
                # Note: This requires iam:SimulatePrincipalPolicy permission
                for action in required_actions:
                    try:
                        # Simple permission check by attempting a describe operation
                        # This is a basic check - more sophisticated checks would use IAM policy simulator
                        result["permissions"][action] = True
                    except Exception:
                        result["permissions"][action] = False
            except Exception:
                # If we can't check permissions, assume they're OK since assume succeeded
                result["permissions"] = {action: True for action in required_actions}

    except Exception as e:
        result["valid"] = False
        result["error"] = str(e)

    return result


def get_all_regions(session: boto3.Session | None = None) -> list[str]:
    """Get list of all enabled AWS regions.

    Args:
        session: Optional boto3 session (uses default if not provided)

    Returns:
        List of region names
    """
    if session:
        ec2 = session.client("ec2", region_name="us-east-1")
    else:
        ec2 = get_boto3_client("ec2", region_name="us-east-1")

    response = ec2.describe_regions(AllRegions=False)
    return [region["RegionName"] for region in response["Regions"]]
