"""Tests for S3 Analyzer."""

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

from botocore.exceptions import ClientError

from analyzers.s3_analyzer import S3Analyzer, handler
from shared.models import FindingSeverity


def _make_analyzer(mock_session=None):
    session = mock_session or MagicMock()
    return S3Analyzer(
        assessment_id=uuid4(),
        account_id="123456789012",
        session=session,
        regions=["us-east-1"],
    )


class TestS3AnalyzerAccountBlock:
    def test_no_account_public_access_block(self):
        analyzer = _make_analyzer()
        mock_s3ctrl = MagicMock()
        mock_s3ctrl.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "none"}},
            "GetPublicAccessBlock",
        )

        analyzer._check_account_public_access_block(mock_s3ctrl)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "not configured" in analyzer.findings[0].title

    def test_partial_account_public_access_block(self):
        analyzer = _make_analyzer()
        mock_s3ctrl = MagicMock()
        mock_s3ctrl.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        analyzer._check_account_public_access_block(mock_s3ctrl)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH

    def test_full_account_public_access_block(self):
        analyzer = _make_analyzer()
        mock_s3ctrl = MagicMock()
        mock_s3ctrl.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        analyzer._check_account_public_access_block(mock_s3ctrl)

        assert len(analyzer.findings) == 0


class TestS3AnalyzerBucketChecks:
    def test_bucket_no_public_access_block(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "none"}},
            "GetPublicAccessBlock",
        )

        analyzer._check_bucket_public_access(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH

    def test_bucket_no_encryption(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "none"}},
            "GetBucketEncryption",
        )

        analyzer._check_bucket_encryption(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM

    def test_bucket_encryption_enabled(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        analyzer._check_bucket_encryption(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 0

    def test_bucket_versioning_disabled(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_versioning.return_value = {}

        analyzer._check_bucket_versioning(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.LOW

    def test_bucket_versioning_enabled(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        analyzer._check_bucket_versioning(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 0

    def test_bucket_no_logging(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_logging.return_value = {}

        analyzer._check_bucket_logging(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.LOW

    def test_public_bucket_policy(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
                ]
            })
        }

        analyzer._check_bucket_policy(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.CRITICAL

    def test_private_bucket_policy(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_policy.return_value = {
            "Policy": json.dumps({
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ]
            })
        }

        analyzer._check_bucket_policy(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 0

    def test_no_bucket_policy(self):
        analyzer = _make_analyzer()
        mock_s3 = MagicMock()
        mock_s3.get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}},
            "GetBucketPolicy",
        )

        analyzer._check_bucket_policy(mock_s3, "test-bucket", "us-east-1")

        assert len(analyzer.findings) == 0


class TestS3AnalyzerHandler:
    @patch("analyzers.s3_analyzer.run_analyzer")
    def test_handler_delegates(self, mock_run):
        mock_run.return_value = {"success": True}
        result = handler({"assessmentId": "test"}, None)
        mock_run.assert_called_once_with(S3Analyzer, {"assessmentId": "test"})
