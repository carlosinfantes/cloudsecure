"""Tests for IAM Analyzer."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from analyzers.iam_analyzer import IAMAnalyzer, handler
from shared.models import FindingSeverity


def _make_analyzer(mock_session=None):
    """Create an IAMAnalyzer with a mock session."""
    session = mock_session or MagicMock()
    return IAMAnalyzer(
        assessment_id=uuid4(),
        account_id="123456789012",
        session=session,
        regions=["us-east-1"],
    )


class TestIAMAnalyzerMFA:
    def test_user_without_mfa_with_console_access(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        # list_users returns one user
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        # No MFA devices
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        # Has console access (login profile exists)
        mock_iam.get_login_profile.return_value = {"LoginProfile": {"UserName": "alice"}}

        analyzer._check_users_without_mfa(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "MFA" in analyzer.findings[0].title

    def test_user_without_mfa_no_console_access(self):
        from botocore.exceptions import ClientError

        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "svc-bot", "Arn": "arn:aws:iam::123456789012:user/svc-bot"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_iam.get_login_profile.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "No login profile"}},
            "GetLoginProfile",
        )

        analyzer._check_users_without_mfa(mock_iam)

        assert len(analyzer.findings) == 0

    def test_user_with_mfa(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "bob", "Arn": "arn:aws:iam::123456789012:user/bob"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator
        mock_iam.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/bob"}]
        }

        analyzer._check_users_without_mfa(mock_iam)

        assert len(analyzer.findings) == 0


class TestIAMAnalyzerAccessKeys:
    def test_old_access_key_detected(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        old_date = datetime.now(UTC) - timedelta(days=120)
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "CreateDate": old_date, "Status": "Active"}
            ]
        }

        analyzer._check_old_access_keys(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM
        assert "120 days" in analyzer.findings[0].title

    def test_recent_access_key_no_finding(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        recent_date = datetime.now(UTC) - timedelta(days=10)
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "CreateDate": recent_date, "Status": "Active"}
            ]
        }

        analyzer._check_old_access_keys(mock_iam)

        assert len(analyzer.findings) == 0


class TestIAMAnalyzerOverprivileged:
    def test_user_with_admin_policy(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Users": [{"UserName": "admin-user", "Arn": "arn:aws:iam::123456789012:user/admin-user"}]}
        ]
        mock_iam.get_paginator.return_value = mock_paginator
        mock_iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ]
        }

        analyzer._check_overprivileged_users(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM
        assert "AdministratorAccess" in analyzer.findings[0].title

    def test_role_with_wildcard_trust(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "open-role",
                        "Arn": "arn:aws:iam::123456789012:role/open-role",
                        "Path": "/",
                        "AssumeRolePolicyDocument": {
                            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
                        },
                    }
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        analyzer._check_overprivileged_roles(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.CRITICAL
        assert "wildcard" in analyzer.findings[0].title

    def test_service_linked_role_skipped(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Roles": [
                    {
                        "RoleName": "AWSServiceRoleForAutoScaling",
                        "Arn": "arn:aws:iam::123456789012:role/aws-service-role/autoscaling",
                        "Path": "/aws-service-role/autoscaling.amazonaws.com/",
                        "AssumeRolePolicyDocument": {
                            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
                        },
                    }
                ]
            }
        ]
        mock_iam.get_paginator.return_value = mock_paginator

        analyzer._check_overprivileged_roles(mock_iam)

        assert len(analyzer.findings) == 0


class TestIAMAnalyzerRootAccount:
    def test_root_no_mfa(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
        }

        analyzer._check_root_account(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.CRITICAL
        assert "MFA" in analyzer.findings[0].title

    def test_root_with_access_keys(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}
        }

        analyzer._check_root_account(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.CRITICAL
        assert "access keys" in analyzer.findings[0].title

    def test_root_secure(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_iam.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }

        analyzer._check_root_account(mock_iam)

        assert len(analyzer.findings) == 0


class TestIAMAnalyzerPasswordPolicy:
    def test_no_password_policy(self):
        from botocore.exceptions import ClientError

        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_iam.get_account_password_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "No policy"}},
            "GetAccountPasswordPolicy",
        )

        analyzer._check_password_policy(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "No IAM password policy" in analyzer.findings[0].title

    def test_weak_password_policy(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        }

        analyzer._check_password_policy(mock_iam)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM

    def test_strong_password_policy(self):
        analyzer = _make_analyzer()
        mock_iam = MagicMock()

        mock_iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        }

        analyzer._check_password_policy(mock_iam)

        assert len(analyzer.findings) == 0


class TestIAMAnalyzerHandler:
    @patch("analyzers.iam_analyzer.run_analyzer")
    def test_handler_delegates(self, mock_run):
        mock_run.return_value = {"success": True}
        result = handler({"assessmentId": "test"}, None)
        mock_run.assert_called_once_with(IAMAnalyzer, {"assessmentId": "test"})
        assert result["success"] is True
