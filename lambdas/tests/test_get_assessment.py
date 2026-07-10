"""Tests for get_assessment API handler."""

import json
from decimal import Decimal
from unittest.mock import MagicMock, patch

from api_handlers.get_assessment import _DecimalEncoder, handler


class TestDecimalEncoder:
    def test_integer_decimal(self):
        assert json.dumps({"v": Decimal("5")}, cls=_DecimalEncoder) == '{"v": 5}'

    def test_float_decimal(self):
        assert json.dumps({"v": Decimal("3.14")}, cls=_DecimalEncoder) == '{"v": 3.14}'

    def test_non_decimal_raises(self):
        import pytest

        with pytest.raises(TypeError):
            json.dumps({"v": object()}, cls=_DecimalEncoder)


class TestGetAssessmentHandler:
    @patch("api_handlers.get_assessment.boto3")
    def test_missing_assessment_id(self, mock_boto3):
        event = {"pathParameters": None}
        resp = handler(event, None)
        assert resp["statusCode"] == 400
        assert "Missing assessmentId" in json.loads(resp["body"])["error"]

    @patch("api_handlers.get_assessment.boto3")
    def test_empty_path_parameters(self, mock_boto3):
        event = {"pathParameters": {}}
        resp = handler(event, None)
        assert resp["statusCode"] == 400

    @patch("api_handlers.get_assessment.boto3")
    def test_assessment_not_found(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}  # No "Item" key
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"pathParameters": {"assessmentId": "nonexistent"}}
        resp = handler(event, None)
        assert resp["statusCode"] == 404

    @patch("api_handlers.get_assessment.boto3")
    def test_valid_assessment(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "assessmentId": "test-123",
                "accountId": "123456789012",
                "status": "COMPLETED",
                "progress": Decimal(100),
                "createdAt": "2026-01-01T00:00:00",
                "findingsCount": Decimal(5),
                "criticalCount": Decimal(1),
                "highCount": Decimal(2),
                "mediumCount": Decimal(1),
                "lowCount": Decimal(1),
                "infoCount": Decimal(0),
                "reportS3Key": "reports/test-123.html",
            }
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"pathParameters": {"assessmentId": "test-123"}}
        resp = handler(event, None)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["assessmentId"] == "test-123"
        assert body["findings"]["total"] == 5
        assert body["findings"]["critical"] == 1
        assert body["reportAvailable"] is True

    @patch("api_handlers.get_assessment.boto3")
    def test_no_report_key(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "assessmentId": "test-123",
                "accountId": "123456789012",
                "status": "RUNNING",
                "createdAt": "2026-01-01T00:00:00",
            }
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"pathParameters": {"assessmentId": "test-123"}}
        resp = handler(event, None)
        body = json.loads(resp["body"])
        assert body["reportAvailable"] is False
