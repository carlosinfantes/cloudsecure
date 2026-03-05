"""Tests for BaseAnalyzer and run_analyzer in analyzers/base.py."""

import logging
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from analyzers.base import BaseAnalyzer, run_analyzer
from shared.models import Finding, FindingSeverity


class _DummyAnalyzer(BaseAnalyzer):
    """Concrete subclass for testing BaseAnalyzer."""

    @property
    def name(self) -> str:
        return "dummy-analyzer"

    def analyze(self) -> list[Finding]:
        self.create_finding(
            severity=FindingSeverity.HIGH,
            title="Test finding",
            description="Test description",
            resource_type="AWS::Test::Resource",
            resource_id="test-resource-1",
        )
        return self.findings


class TestBaseAnalyzer:
    def test_create_finding_appends_to_findings(self, mock_boto3_session):
        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="123456789012",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        finding = analyzer.create_finding(
            severity=FindingSeverity.MEDIUM,
            title="Test",
            description="Desc",
            resource_type="AWS::S3::Bucket",
            resource_id="my-bucket",
        )
        assert len(analyzer.findings) == 1
        assert analyzer.findings[0] is finding

    def test_create_finding_sets_source_from_name(self, mock_boto3_session):
        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="123456789012",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        finding = analyzer.create_finding(
            severity=FindingSeverity.LOW,
            title="T",
            description="D",
            resource_type="AWS::IAM::User",
            resource_id="user1",
        )
        assert finding.source == "dummy-analyzer"

    def test_create_finding_sets_account_id(self, mock_boto3_session):
        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="999888777666",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        finding = analyzer.create_finding(
            severity=FindingSeverity.INFO,
            title="T",
            description="D",
            resource_type="AWS::EC2::Instance",
            resource_id="i-123",
        )
        assert finding.account_id == "999888777666"

    def test_get_client_delegates_to_session(self, mock_boto3_session):
        mock_client = MagicMock()
        mock_boto3_session.client.return_value = mock_client

        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="123456789012",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        result = analyzer.get_client("s3", "eu-west-1")

        mock_boto3_session.client.assert_called_once_with("s3", region_name="eu-west-1")
        assert result is mock_client

    def test_get_client_defaults_to_us_east_1(self, mock_boto3_session):
        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="123456789012",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        analyzer.get_client("iam")

        mock_boto3_session.client.assert_called_once_with("iam", region_name="us-east-1")

    def test_log_info_includes_analyzer_name(self, mock_boto3_session, caplog):
        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="123456789012",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        with caplog.at_level(logging.INFO):
            analyzer.log_info("test message")
        assert "[dummy-analyzer] test message" in caplog.text

    def test_log_error_includes_analyzer_name(self, mock_boto3_session, caplog):
        analyzer = _DummyAnalyzer(
            assessment_id=uuid4(),
            account_id="123456789012",
            session=mock_boto3_session,
            regions=["us-east-1"],
        )
        with caplog.at_level(logging.ERROR):
            analyzer.log_error("error msg")
        assert "[dummy-analyzer] error msg" in caplog.text


class TestRunAnalyzer:
    @patch("analyzers.base.get_assumed_role_session")
    def test_success_returns_findings(self, mock_get_session):
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        event = {
            "assessmentId": str(uuid4()),
            "accountId": "123456789012",
            "roleArn": "arn:aws:iam::123456789012:role/Test",
            "externalId": "ext-123",
            "regions": ["us-east-1"],
            "scope": ["all"],
        }
        result = run_analyzer(_DummyAnalyzer, event)

        assert result["success"] is True
        assert result["findingsCount"] == 1
        assert result["analyzer"] == "dummy-analyzer"
        assert result["summary"]["high"] == 1

    @patch("analyzers.base.get_assumed_role_session")
    def test_handles_client_error(self, mock_get_session):
        mock_get_session.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}},
            "AssumeRole",
        )

        event = {
            "assessmentId": str(uuid4()),
            "accountId": "123456789012",
            "roleArn": "arn:aws:iam::123456789012:role/Test",
            "externalId": "ext-123",
        }
        result = run_analyzer(_DummyAnalyzer, event)

        assert result["success"] is False
        assert "AccessDenied" in result["error"]

    @patch("analyzers.base.get_assumed_role_session")
    def test_handles_generic_exception(self, mock_get_session):
        mock_get_session.side_effect = ValueError("something broke")

        event = {
            "assessmentId": str(uuid4()),
            "accountId": "123456789012",
            "roleArn": "arn:aws:iam::123456789012:role/Test",
            "externalId": "ext-123",
        }
        result = run_analyzer(_DummyAnalyzer, event)

        assert result["success"] is False
        assert "something broke" in result["error"]

    @patch("analyzers.base.get_assumed_role_session")
    def test_findings_data_format(self, mock_get_session):
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        event = {
            "assessmentId": str(uuid4()),
            "accountId": "123456789012",
            "roleArn": "arn:aws:iam::123456789012:role/Test",
            "externalId": "ext-123",
            "regions": ["us-east-1"],
        }
        result = run_analyzer(_DummyAnalyzer, event)

        assert len(result["findings"]) == 1
        fd = result["findings"][0]
        assert "findingId" in fd
        assert fd["severity"] == "HIGH"
        assert fd["title"] == "Test finding"
        assert fd["resourceType"] == "AWS::Test::Resource"
