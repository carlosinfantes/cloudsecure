"""IAM Analyzer - Detects IAM security issues.

Checks for:
1. Users without MFA enabled
2. Unused credentials (>90 days)
3. Overprivileged users/roles (admin access)
4. Access keys older than 90 days
5. Root account usage
6. Cross-account trust policies
"""

import logging
import os
import sys
from datetime import UTC, datetime, timedelta
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

# Thresholds
CREDENTIAL_AGE_THRESHOLD_DAYS = 90
ACCESS_KEY_AGE_THRESHOLD_DAYS = 90


class IAMAnalyzer(BaseAnalyzer):
    """Analyzer for IAM security issues."""

    @property
    def name(self) -> str:
        return "iam-analyzer"

    def analyze(self) -> list[Finding]:
        """Run IAM security analysis."""
        self.log_info("Starting IAM analysis")

        # IAM is a global service
        iam = self.get_client("iam")

        # Run all checks
        self._check_users_without_mfa(iam)
        self._check_unused_credentials(iam)
        self._check_old_access_keys(iam)
        self._check_overprivileged_users(iam)
        self._check_overprivileged_roles(iam)
        self._check_root_account(iam)
        self._check_password_policy(iam)

        self.log_info(f"IAM analysis complete. Found {len(self.findings)} findings")
        return self.findings

    def _check_users_without_mfa(self, iam: Any) -> None:
        """Check for IAM users without MFA enabled."""
        self.log_info("Checking for users without MFA")

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # Check if user has MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)

                    if not mfa_devices["MFADevices"]:
                        # Check if user has console access (password)
                        try:
                            iam.get_login_profile(UserName=username)
                            has_console_access = True
                        except ClientError as e:
                            if e.response["Error"]["Code"] == "NoSuchEntity":
                                has_console_access = False
                            else:
                                raise

                        if has_console_access:
                            self.create_finding(
                                severity=FindingSeverity.HIGH,
                                title=f"IAM user '{username}' does not have MFA enabled",
                                description=(
                                    f"The IAM user '{username}' has console access but does not have "
                                    "multi-factor authentication (MFA) enabled. This significantly "
                                    "increases the risk of account compromise."
                                ),
                                resource_type="AWS::IAM::User",
                                resource_id=username,
                                resource_arn=user["Arn"],
                                compliance_mappings=[
                                    ComplianceMapping(
                                        framework=ComplianceFramework.CIS_AWS_1_4,
                                        control="1.10",
                                        description="Ensure MFA is enabled for all IAM users with console password",
                                    ),
                                ],
                                remediation=Remediation(
                                    description="Enable MFA for this IAM user",
                                    steps=[
                                        "Sign in to the AWS Management Console",
                                        "Navigate to IAM > Users > " + username,
                                        "Select the 'Security credentials' tab",
                                        "Click 'Manage' next to 'Assigned MFA device'",
                                        "Follow the wizard to configure a virtual or hardware MFA device",
                                    ],
                                    automatable=False,
                                    effort="LOW",
                                ),
                            )

        except ClientError as e:
            self.log_error(f"Error checking MFA: {e}")

    def _check_unused_credentials(self, iam: Any) -> None:
        """Check for unused credentials (not used in 90+ days)."""
        self.log_info("Checking for unused credentials")

        try:
            # Generate credential report
            try:  # noqa: SIM105
                iam.generate_credential_report()
            except ClientError:
                pass  # Report might already be generating

            # Get credential report (may need to retry)
            import time

            for _ in range(5):
                try:
                    response = iam.get_credential_report()
                    break
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ReportNotPresent":
                        time.sleep(2)
                    else:
                        raise
            else:
                self.log_warning("Could not generate credential report")
                return

            # Parse CSV report
            import csv
            import io

            report = response["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(report))

            threshold_date = datetime.now(UTC) - timedelta(days=CREDENTIAL_AGE_THRESHOLD_DAYS)

            for row in reader:
                username = row["user"]

                # Skip root account (handled separately)
                if username == "<root_account>":
                    continue

                # Check password last used
                password_last_used = row.get("password_last_used", "N/A")
                if password_last_used not in ["N/A", "no_information", "not_supported"]:
                    try:
                        last_used = datetime.fromisoformat(
                            password_last_used.replace("Z", "+00:00")
                        )
                        if last_used < threshold_date:
                            self.create_finding(
                                severity=FindingSeverity.MEDIUM,
                                title=f"IAM user '{username}' has unused password credentials",
                                description=(
                                    f"The IAM user '{username}' has not used their password to sign in "
                                    f"for over {CREDENTIAL_AGE_THRESHOLD_DAYS} days (last used: {password_last_used}). "
                                    "Unused credentials should be disabled or removed."
                                ),
                                resource_type="AWS::IAM::User",
                                resource_id=username,
                                compliance_mappings=[
                                    ComplianceMapping(
                                        framework=ComplianceFramework.CIS_AWS_1_4,
                                        control="1.12",
                                        description="Ensure credentials unused for 90 days or greater are disabled",
                                    ),
                                ],
                                remediation=Remediation(
                                    description="Disable or remove unused credentials",
                                    steps=[
                                        "Verify with the user if they still need access",
                                        "If not needed, delete the user or disable console access",
                                        f"Navigate to IAM > Users > {username} > Security credentials",
                                        "Disable or delete the login profile",
                                    ],
                                    automatable=True,
                                    effort="LOW",
                                ),
                            )
                    except (ValueError, TypeError):
                        pass

        except ClientError as e:
            self.log_error(f"Error checking unused credentials: {e}")

    def _check_old_access_keys(self, iam: Any) -> None:
        """Check for access keys older than 90 days."""
        self.log_info("Checking for old access keys")

        try:
            threshold_date = datetime.now(UTC) - timedelta(days=ACCESS_KEY_AGE_THRESHOLD_DAYS)

            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # List access keys for user
                    keys_response = iam.list_access_keys(UserName=username)

                    for key in keys_response["AccessKeyMetadata"]:
                        key_id = key["AccessKeyId"]
                        create_date = key["CreateDate"]

                        if create_date.replace(tzinfo=UTC) < threshold_date:
                            age_days = (datetime.now(UTC) - create_date.replace(tzinfo=UTC)).days

                            self.create_finding(
                                severity=FindingSeverity.MEDIUM,
                                title=f"Access key '{key_id[:8]}...' for user '{username}' is {age_days} days old",
                                description=(
                                    f"The access key '{key_id}' for IAM user '{username}' was created "
                                    f"{age_days} days ago. Access keys should be rotated regularly "
                                    f"(at least every {ACCESS_KEY_AGE_THRESHOLD_DAYS} days)."
                                ),
                                resource_type="AWS::IAM::AccessKey",
                                resource_id=key_id,
                                compliance_mappings=[
                                    ComplianceMapping(
                                        framework=ComplianceFramework.CIS_AWS_1_4,
                                        control="1.14",
                                        description="Ensure access keys are rotated every 90 days or less",
                                    ),
                                ],
                                remediation=Remediation(
                                    description="Rotate the access key",
                                    steps=[
                                        f"Create a new access key for user {username}",
                                        "Update all applications using the old key",
                                        "Test that applications work with the new key",
                                        f"Deactivate and delete the old key {key_id}",
                                    ],
                                    automatable=True,
                                    effort="MEDIUM",
                                ),
                                metadata={
                                    "keyAge": age_days,
                                    "createDate": create_date.isoformat(),
                                },
                            )

        except ClientError as e:
            self.log_error(f"Error checking access keys: {e}")

    def _check_overprivileged_users(self, iam: Any) -> None:
        """Check for users with administrator access."""
        self.log_info("Checking for overprivileged users")

        admin_policies = [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess",
        ]

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # Check attached policies
                    attached = iam.list_attached_user_policies(UserName=username)
                    for policy in attached["AttachedPolicies"]:
                        if policy["PolicyArn"] in admin_policies:
                            self.create_finding(
                                severity=FindingSeverity.MEDIUM,
                                title=f"IAM user '{username}' has {policy['PolicyName']} attached",
                                description=(
                                    f"The IAM user '{username}' has the '{policy['PolicyName']}' policy "
                                    "directly attached. This grants excessive permissions. Consider using "
                                    "more restrictive policies based on the principle of least privilege."
                                ),
                                resource_type="AWS::IAM::User",
                                resource_id=username,
                                resource_arn=user["Arn"],
                                remediation=Remediation(
                                    description="Apply least privilege access",
                                    steps=[
                                        "Review the user's actual permission requirements",
                                        "Create or use a more restrictive policy",
                                        f"Detach {policy['PolicyName']} from the user",
                                        "Attach the restrictive policy instead",
                                    ],
                                    automatable=False,
                                    effort="MEDIUM",
                                ),
                            )

        except ClientError as e:
            self.log_error(f"Error checking overprivileged users: {e}")

    def _check_overprivileged_roles(self, iam: Any) -> None:
        """Check for roles with administrator access and permissive trust policies."""
        self.log_info("Checking for overprivileged roles")

        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]

                    # Skip AWS service-linked roles
                    if role["Path"].startswith("/aws-service-role/"):
                        continue

                    # Check trust policy for overly permissive principals
                    trust_policy = role["AssumeRolePolicyDocument"]
                    for statement in trust_policy.get("Statement", []):
                        principal = statement.get("Principal", {})

                        # Check for wildcard principal
                        if principal == "*" or principal.get("AWS") == "*":
                            self.create_finding(
                                severity=FindingSeverity.CRITICAL,
                                title=f"IAM role '{role_name}' has wildcard trust policy",
                                description=(
                                    f"The IAM role '{role_name}' can be assumed by any AWS principal. "
                                    "This is extremely dangerous and could allow any AWS account to "
                                    "assume this role."
                                ),
                                resource_type="AWS::IAM::Role",
                                resource_id=role_name,
                                resource_arn=role["Arn"],
                                compliance_mappings=[
                                    ComplianceMapping(
                                        framework=ComplianceFramework.CIS_AWS_1_4,
                                        control="1.16",
                                        description="Ensure IAM policies are attached only to groups or roles",
                                    ),
                                ],
                                remediation=Remediation(
                                    description="Restrict the trust policy",
                                    steps=[
                                        "Identify which principals should be able to assume this role",
                                        "Update the trust policy to explicitly list allowed principals",
                                        "Add conditions like ExternalId for cross-account access",
                                    ],
                                    automatable=False,
                                    effort="MEDIUM",
                                ),
                            )

        except ClientError as e:
            self.log_error(f"Error checking roles: {e}")

    def _check_root_account(self, iam: Any) -> None:
        """Check root account security settings."""
        self.log_info("Checking root account security")

        try:
            # Get account summary
            summary = iam.get_account_summary()["SummaryMap"]

            # Check if root has MFA
            if summary.get("AccountMFAEnabled", 0) == 0:
                self.create_finding(
                    severity=FindingSeverity.CRITICAL,
                    title="Root account does not have MFA enabled",
                    description=(
                        "The AWS root account does not have multi-factor authentication (MFA) enabled. "
                        "The root account has unrestricted access to all resources and should be "
                        "protected with MFA."
                    ),
                    resource_type="AWS::IAM::Root",
                    resource_id="root",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="1.5",
                            description="Ensure MFA is enabled for the root account",
                        ),
                    ],
                    remediation=Remediation(
                        description="Enable MFA for the root account",
                        steps=[
                            "Sign in to the AWS Console as root",
                            "Navigate to My Security Credentials",
                            "Expand the Multi-factor authentication (MFA) section",
                            "Click 'Activate MFA' and follow the wizard",
                            "Use a hardware MFA device for maximum security",
                        ],
                        automatable=False,
                        effort="LOW",
                    ),
                )

            # Check if root has access keys
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                self.create_finding(
                    severity=FindingSeverity.CRITICAL,
                    title="Root account has active access keys",
                    description=(
                        "The AWS root account has active access keys. Access keys for the root account "
                        "should be deleted. Use IAM users or roles for programmatic access instead."
                    ),
                    resource_type="AWS::IAM::Root",
                    resource_id="root",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="1.4",
                            description="Ensure no root account access key exists",
                        ),
                    ],
                    remediation=Remediation(
                        description="Delete root account access keys",
                        steps=[
                            "Sign in to the AWS Console as root",
                            "Navigate to My Security Credentials",
                            "Expand the Access keys section",
                            "Delete all access keys",
                            "Create IAM users with appropriate permissions instead",
                        ],
                        automatable=False,
                        effort="LOW",
                    ),
                )

        except ClientError as e:
            self.log_error(f"Error checking root account: {e}")

    def _check_password_policy(self, iam: Any) -> None:
        """Check account password policy."""
        self.log_info("Checking password policy")

        try:
            try:
                policy = iam.get_account_password_policy()["PasswordPolicy"]
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    self.create_finding(
                        severity=FindingSeverity.HIGH,
                        title="No IAM password policy is configured",
                        description=(
                            "The AWS account does not have a custom password policy configured. "
                            "This means the default (weak) password requirements are in effect."
                        ),
                        resource_type="AWS::IAM::AccountPasswordPolicy",
                        resource_id="password-policy",
                        compliance_mappings=[
                            ComplianceMapping(
                                framework=ComplianceFramework.CIS_AWS_1_4,
                                control="1.8",
                                description="Ensure IAM password policy requires minimum length of 14 or greater",
                            ),
                        ],
                        remediation=Remediation(
                            description="Configure a strong password policy",
                            steps=[
                                "Navigate to IAM > Account settings",
                                "Click 'Change password policy'",
                                "Set minimum length to 14 characters",
                                "Require uppercase, lowercase, numbers, and symbols",
                                "Enable password expiration (90 days recommended)",
                                "Prevent password reuse (24 passwords recommended)",
                            ],
                            automatable=True,
                            effort="LOW",
                        ),
                    )
                    return
                raise

            # Check specific policy settings
            issues = []

            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append(
                    f"Minimum length is {policy.get('MinimumPasswordLength', 0)} (should be 14+)"
                )

            if not policy.get("RequireUppercaseCharacters", False):
                issues.append("Does not require uppercase characters")

            if not policy.get("RequireLowercaseCharacters", False):
                issues.append("Does not require lowercase characters")

            if not policy.get("RequireNumbers", False):
                issues.append("Does not require numbers")

            if not policy.get("RequireSymbols", False):
                issues.append("Does not require symbols")

            if issues:
                self.create_finding(
                    severity=FindingSeverity.MEDIUM,
                    title="IAM password policy does not meet security best practices",
                    description=(
                        "The IAM password policy has the following issues: " + "; ".join(issues)
                    ),
                    resource_type="AWS::IAM::AccountPasswordPolicy",
                    resource_id="password-policy",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="1.8",
                            description="Ensure IAM password policy requires minimum length of 14 or greater",
                        ),
                    ],
                    remediation=Remediation(
                        description="Strengthen the password policy",
                        steps=[
                            "Navigate to IAM > Account settings",
                            "Update the password policy to address the issues",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                    metadata={"issues": issues},
                )

        except ClientError as e:
            self.log_error(f"Error checking password policy: {e}")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for IAM analysis."""
    return run_analyzer(IAMAnalyzer, event)
