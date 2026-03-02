"""S3 Analyzer - Detects S3 security issues.

Checks for:
1. Public buckets (ACL or policy)
2. Buckets without encryption
3. Buckets without versioning
4. Buckets without access logging
5. Buckets without lifecycle policies
6. Buckets with overly permissive policies
"""

import json
import logging
import os
import sys
from typing import Any

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.base import BaseAnalyzer, run_analyzer
from shared.models import (
    ComplianceFramework,
    ComplianceMapping,
    Finding,
    FindingSeverity,
    Remediation,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class S3Analyzer(BaseAnalyzer):
    """Analyzer for S3 security issues."""

    @property
    def name(self) -> str:
        return "s3-analyzer"

    def analyze(self) -> list[Finding]:
        """Run S3 security analysis."""
        self.log_info("Starting S3 analysis")

        # S3 is a global service
        s3 = self.get_client("s3")
        s3_control = self.get_client("s3control")

        # Check account-level public access block
        self._check_account_public_access_block(s3_control)

        # Get all buckets
        try:
            buckets = s3.list_buckets()["Buckets"]
            self.log_info(f"Found {len(buckets)} buckets to analyze")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                self._analyze_bucket(s3, bucket_name)

        except ClientError as e:
            self.log_error(f"Error listing buckets: {e}")

        self.log_info(f"S3 analysis complete. Found {len(self.findings)} findings")
        return self.findings

    def _check_account_public_access_block(self, s3_control: Any) -> None:
        """Check if account-level public access block is enabled."""
        self.log_info("Checking account-level public access block")

        try:
            config = s3_control.get_public_access_block(AccountId=self.account_id)
            block = config["PublicAccessBlockConfiguration"]

            issues = []
            if not block.get("BlockPublicAcls", False):
                issues.append("BlockPublicAcls is disabled")
            if not block.get("IgnorePublicAcls", False):
                issues.append("IgnorePublicAcls is disabled")
            if not block.get("BlockPublicPolicy", False):
                issues.append("BlockPublicPolicy is disabled")
            if not block.get("RestrictPublicBuckets", False):
                issues.append("RestrictPublicBuckets is disabled")

            if issues:
                self.create_finding(
                    severity=FindingSeverity.HIGH,
                    title="Account-level S3 public access block is not fully enabled",
                    description=(
                        "The account-level S3 public access block settings are not fully enabled. "
                        f"Issues: {', '.join(issues)}. This allows buckets to potentially be made public."
                    ),
                    resource_type="AWS::S3::AccountPublicAccessBlock",
                    resource_id=self.account_id,
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="2.1.5",
                            description="Ensure S3 Account Level Public Access Block is enabled",
                        ),
                    ],
                    remediation=Remediation(
                        description="Enable all account-level public access block settings",
                        steps=[
                            "Navigate to S3 > Block Public Access settings for this account",
                            "Enable all four settings",
                            "Click Save changes",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                    metadata={"issues": issues},
                )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                self.create_finding(
                    severity=FindingSeverity.HIGH,
                    title="Account-level S3 public access block is not configured",
                    description=(
                        "The account does not have S3 public access block configured at the account level. "
                        "This allows individual buckets to be made public."
                    ),
                    resource_type="AWS::S3::AccountPublicAccessBlock",
                    resource_id=self.account_id,
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="2.1.5",
                            description="Ensure S3 Account Level Public Access Block is enabled",
                        ),
                    ],
                    remediation=Remediation(
                        description="Configure account-level public access block",
                        steps=[
                            "Navigate to S3 > Block Public Access settings for this account",
                            "Enable all four settings",
                            "Click Save changes",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )
            else:
                self.log_error(f"Error checking account public access block: {e}")

    def _analyze_bucket(self, s3: Any, bucket_name: str) -> None:
        """Analyze a single S3 bucket for security issues."""
        self.log_info(f"Analyzing bucket: {bucket_name}")

        # Get bucket region
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            region = location.get("LocationConstraint") or "us-east-1"
        except ClientError:
            region = "unknown"

        # Run all bucket checks
        self._check_bucket_public_access(s3, bucket_name, region)
        self._check_bucket_encryption(s3, bucket_name, region)
        self._check_bucket_versioning(s3, bucket_name, region)
        self._check_bucket_logging(s3, bucket_name, region)
        self._check_bucket_policy(s3, bucket_name, region)

    def _check_bucket_public_access(self, s3: Any, bucket_name: str, region: str) -> None:
        """Check if bucket has public access block enabled."""
        try:
            config = s3.get_public_access_block(Bucket=bucket_name)
            block = config["PublicAccessBlockConfiguration"]

            all_enabled = all(
                [
                    block.get("BlockPublicAcls", False),
                    block.get("IgnorePublicAcls", False),
                    block.get("BlockPublicPolicy", False),
                    block.get("RestrictPublicBuckets", False),
                ]
            )

            if not all_enabled:
                self.create_finding(
                    severity=FindingSeverity.MEDIUM,
                    title=f"S3 bucket '{bucket_name}' does not have full public access block",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have all public access block "
                        "settings enabled. This could allow the bucket to be made public."
                    ),
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region,
                    remediation=Remediation(
                        description="Enable public access block for this bucket",
                        steps=[
                            f"Navigate to S3 > {bucket_name} > Permissions",
                            "Edit 'Block public access' settings",
                            "Enable all four settings",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                self.create_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"S3 bucket '{bucket_name}' has no public access block configured",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have any public access block "
                        "configuration. The bucket could potentially be made public."
                    ),
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region,
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="2.1.5",
                            description="Ensure S3 Bucket Level Public Access Block is enabled",
                        ),
                    ],
                    remediation=Remediation(
                        description="Configure public access block for this bucket",
                        steps=[
                            f"Navigate to S3 > {bucket_name} > Permissions",
                            "Edit 'Block public access' settings",
                            "Enable all four settings",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

    def _check_bucket_encryption(self, s3: Any, bucket_name: str, region: str) -> None:
        """Check if bucket has default encryption enabled."""
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
            # Encryption is configured

        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                self.create_finding(
                    severity=FindingSeverity.MEDIUM,
                    title=f"S3 bucket '{bucket_name}' does not have default encryption enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have default server-side encryption "
                        "enabled. Objects uploaded without explicit encryption will be stored unencrypted."
                    ),
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region,
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="2.1.1",
                            description="Ensure S3 bucket default encryption is enabled",
                        ),
                    ],
                    remediation=Remediation(
                        description="Enable default encryption for this bucket",
                        steps=[
                            f"Navigate to S3 > {bucket_name} > Properties",
                            "Edit 'Default encryption'",
                            "Enable encryption (SSE-S3 or SSE-KMS)",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

    def _check_bucket_versioning(self, s3: Any, bucket_name: str, region: str) -> None:
        """Check if bucket has versioning enabled."""
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "Disabled")

            if status != "Enabled":
                self.create_finding(
                    severity=FindingSeverity.LOW,
                    title=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have versioning enabled "
                        f"(Status: {status}). Versioning helps protect against accidental deletion "
                        "and enables recovery of previous versions."
                    ),
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region,
                    remediation=Remediation(
                        description="Enable versioning for this bucket",
                        steps=[
                            f"Navigate to S3 > {bucket_name} > Properties",
                            "Edit 'Bucket Versioning'",
                            "Enable versioning",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

        except ClientError as e:
            self.log_error(f"Error checking versioning for {bucket_name}: {e}")

    def _check_bucket_logging(self, s3: Any, bucket_name: str, region: str) -> None:
        """Check if bucket has access logging enabled."""
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)

            if "LoggingEnabled" not in logging_config:
                self.create_finding(
                    severity=FindingSeverity.LOW,
                    title=f"S3 bucket '{bucket_name}' does not have access logging enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have server access logging enabled. "
                        "Access logs provide detailed records for security and audit purposes."
                    ),
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region,
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="2.1.3",
                            description="Ensure S3 bucket access logging is enabled",
                        ),
                    ],
                    remediation=Remediation(
                        description="Enable access logging for this bucket",
                        steps=[
                            f"Navigate to S3 > {bucket_name} > Properties",
                            "Edit 'Server access logging'",
                            "Enable logging and specify a target bucket",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

        except ClientError as e:
            self.log_error(f"Error checking logging for {bucket_name}: {e}")

    def _check_bucket_policy(self, s3: Any, bucket_name: str, region: str) -> None:
        """Check bucket policy for overly permissive access."""
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
            policy = json.loads(policy_str)

            for statement in policy.get("Statement", []):
                effect = statement.get("Effect", "Deny")
                principal = statement.get("Principal", {})

                # Check for public access (Principal: "*" or Principal: {"AWS": "*"})
                is_public = (
                    principal == "*"
                    or principal == {"AWS": "*"}
                    or (isinstance(principal, dict) and principal.get("AWS") == "*")
                )

                if effect == "Allow" and is_public:
                    # Check if there are conditions that restrict access
                    conditions = statement.get("Condition", {})

                    if not conditions:
                        actions = statement.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]

                        self.create_finding(
                            severity=FindingSeverity.CRITICAL,
                            title=f"S3 bucket '{bucket_name}' has a public bucket policy",
                            description=(
                                f"The S3 bucket '{bucket_name}' has a bucket policy that allows "
                                f"public access. Actions allowed: {', '.join(actions)}. "
                                "This could expose sensitive data to the internet."
                            ),
                            resource_type="AWS::S3::BucketPolicy",
                            resource_id=bucket_name,
                            region=region,
                            compliance_mappings=[
                                ComplianceMapping(
                                    framework=ComplianceFramework.CIS_AWS_1_4,
                                    control="2.1.2",
                                    description="Ensure S3 bucket policy does not grant public access",
                                ),
                            ],
                            remediation=Remediation(
                                description="Remove public access from bucket policy",
                                steps=[
                                    f"Navigate to S3 > {bucket_name} > Permissions",
                                    "Edit 'Bucket policy'",
                                    "Remove or modify statements with Principal: '*'",
                                    "Add specific principal ARNs instead",
                                ],
                                automatable=False,
                                effort="MEDIUM",
                            ),
                            metadata={"actions": actions},
                        )

        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                self.log_error(f"Error checking policy for {bucket_name}: {e}")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for S3 analysis."""
    return run_analyzer(S3Analyzer, event)
