"""Tests for start_assessment API handler."""

import json
from unittest.mock import MagicMock, patch

from api_handlers.start_assessment import api_response, handler


def _event(body=None):
    """Build an API Gateway event."""
    return {"body": json.dumps(body) if body else "{}"}


class TestApiResponse:
    def test_structure(self):
        resp = api_response(200, {"ok": True})
        assert resp["statusCode"] == 200
        assert resp["headers"]["Content-Type"] == "application/json"
        assert resp["headers"]["Access-Control-Allow-Origin"] == "*"
        assert json.loads(resp["body"]) == {"ok": True}


class TestStartAssessmentHandler:
    @patch("api_handlers.start_assessment.boto3")
    def test_missing_required_fields(self, mock_boto3):
        resp = handler(_event({"accountId": "123456789012"}), None)
        assert resp["statusCode"] == 400
        body = json.loads(resp["body"])
        assert "missingFields" in body
        assert "roleArn" in body["missingFields"]
        assert "externalId" in body["missingFields"]

    @patch("api_handlers.start_assessment.boto3")
    def test_invalid_account_id_not_12_digits(self, mock_boto3):
        resp = handler(
            _event(
                {
                    "accountId": "12345",
                    "roleArn": "arn:aws:iam:::role/Test",
                    "externalId": "ext-123",
                }
            ),
            None,
        )
        assert resp["statusCode"] == 400
        assert "Invalid accountId" in json.loads(resp["body"])["error"]

    @patch("api_handlers.start_assessment.boto3")
    def test_invalid_account_id_not_digits(self, mock_boto3):
        resp = handler(
            _event(
                {
                    "accountId": "12345678901a",
                    "roleArn": "arn:aws:iam:::role/Test",
                    "externalId": "ext-123",
                }
            ),
            None,
        )
        assert resp["statusCode"] == 400

    @patch("api_handlers.start_assessment.boto3")
    def test_invalid_role_arn(self, mock_boto3):
        resp = handler(
            _event(
                {
                    "accountId": "123456789012",
                    "roleArn": "invalid-arn",
                    "externalId": "ext-123",
                }
            ),
            None,
        )
        assert resp["statusCode"] == 400
        assert "Invalid roleArn" in json.loads(resp["body"])["error"]

    def test_invalid_json_body(self):
        resp = handler({"body": "not-json{"}, None)
        assert resp["statusCode"] == 400
        assert "Invalid JSON" in json.loads(resp["body"])["error"]

    @patch("api_handlers.start_assessment.boto3")
    def test_invalid_compliance_framework(self, mock_boto3):
        resp = handler(
            _event(
                {
                    "accountId": "123456789012",
                    "roleArn": "arn:aws:iam:::role/Test",
                    "externalId": "ext-123",
                    "complianceFrameworks": ["INVALID_FRAMEWORK"],
                }
            ),
            None,
        )
        assert resp["statusCode"] == 400
        body = json.loads(resp["body"])
        assert "Invalid compliance framework" in body["error"]
        assert "validFrameworks" in body

    @patch("api_handlers.start_assessment.boto3")
    def test_valid_request_returns_201(self, mock_boto3):
        mock_table = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_table
        mock_sfn = MagicMock()
        mock_sfn.start_execution.return_value = {"executionArn": "arn:aws:states:::exec"}
        mock_boto3.client.return_value = mock_sfn

        resp = handler(
            _event(
                {
                    "accountId": "123456789012",
                    "roleArn": "arn:aws:iam:::role/CloudSecureReadOnly",
                    "externalId": "ext-123",
                }
            ),
            None,
        )
        assert resp["statusCode"] == 201
        body = json.loads(resp["body"])
        assert "assessmentId" in body
        assert body["status"] == "PENDING"
        mock_table.put_item.assert_called_once()

    @patch("api_handlers.start_assessment.boto3")
    @patch("api_handlers.start_assessment.STATE_MACHINE_ARN", "arn:aws:states:::sm")
    def test_sfn_failure_returns_500(self, mock_boto3):
        from botocore.exceptions import ClientError

        mock_table = MagicMock()
        mock_boto3.resource.return_value.Table.return_value = mock_table
        mock_sfn = MagicMock()
        mock_sfn.start_execution.side_effect = ClientError(
            {"Error": {"Code": "ExecutionAlreadyExists", "Message": "dup"}},
            "StartExecution",
        )
        mock_boto3.client.return_value = mock_sfn

        resp = handler(
            _event(
                {
                    "accountId": "123456789012",
                    "roleArn": "arn:aws:iam:::role/CloudSecureReadOnly",
                    "externalId": "ext-123",
                }
            ),
            None,
        )
        assert resp["statusCode"] == 500
        body = json.loads(resp["body"])
        assert "assessmentId" in body
