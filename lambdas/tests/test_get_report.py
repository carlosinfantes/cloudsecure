"""Tests for get_report API handler."""

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from api_handlers.get_report import handler


class TestGetReportHandler:
    @patch("api_handlers.get_report.boto3")
    def test_missing_assessment_id(self, mock_boto3):
        event = {"pathParameters": None, "queryStringParameters": None}
        resp = handler(event, None)
        assert resp["statusCode"] == 400
        assert "Missing assessmentId" in json.loads(resp["body"])["error"]

    @patch("api_handlers.get_report.boto3")
    def test_invalid_format(self, mock_boto3):
        event = {
            "pathParameters": {"assessmentId": "test-123"},
            "queryStringParameters": {"format": "xml"},
        }
        resp = handler(event, None)
        assert resp["statusCode"] == 400
        assert "Invalid format" in json.loads(resp["body"])["error"]

    @patch("api_handlers.get_report.boto3")
    def test_assessment_not_found(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {
            "pathParameters": {"assessmentId": "test-123"},
            "queryStringParameters": {"format": "html"},
        }
        resp = handler(event, None)
        assert resp["statusCode"] == 404

    @patch("api_handlers.get_report.boto3")
    def test_assessment_not_completed(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"assessmentId": "test-123", "status": "RUNNING", "progress": 50}
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {
            "pathParameters": {"assessmentId": "test-123"},
            "queryStringParameters": {"format": "html"},
        }
        resp = handler(event, None)
        assert resp["statusCode"] == 400
        body = json.loads(resp["body"])
        assert "not completed" in body["error"]

    @patch("api_handlers.get_report.boto3")
    def test_no_report_key(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"assessmentId": "test-123", "status": "COMPLETED"}
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {
            "pathParameters": {"assessmentId": "test-123"},
            "queryStringParameters": {"format": "html"},
        }
        resp = handler(event, None)
        assert resp["statusCode"] == 404
        assert "not yet generated" in json.loads(resp["body"])["error"]

    @patch("api_handlers.get_report.boto3")
    def test_valid_request_returns_presigned_url(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "assessmentId": "test-123",
                "status": "COMPLETED",
                "reportS3Key": "reports/test-123.html",
            }
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        mock_s3 = MagicMock()
        mock_s3.generate_presigned_url.return_value = "https://s3.example.com/signed-url"
        mock_boto3.client.return_value = mock_s3

        event = {
            "pathParameters": {"assessmentId": "test-123"},
            "queryStringParameters": {"format": "json"},
        }
        resp = handler(event, None)
        assert resp["statusCode"] == 200
        body = json.loads(resp["body"])
        assert body["downloadUrl"] == "https://s3.example.com/signed-url"
        assert body["format"] == "json"

        # Verify S3 key uses requested format
        head_call = mock_s3.head_object.call_args
        assert head_call[1]["Key"] == "reports/test-123.json"

    @patch("api_handlers.get_report.boto3")
    def test_s3_file_not_found(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "assessmentId": "test-123",
                "status": "COMPLETED",
                "reportS3Key": "reports/test-123.html",
            }
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = ClientError(
            {"Error": {"Code": "404", "Message": "Not Found"}},
            "HeadObject",
        )
        mock_boto3.client.return_value = mock_s3

        event = {
            "pathParameters": {"assessmentId": "test-123"},
            "queryStringParameters": {"format": "csv"},
        }
        resp = handler(event, None)
        assert resp["statusCode"] == 404
        assert "not available" in json.loads(resp["body"])["error"]
