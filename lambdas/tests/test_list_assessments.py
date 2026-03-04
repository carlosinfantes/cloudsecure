"""Tests for list_assessments API handler."""

import json
from decimal import Decimal
from unittest.mock import MagicMock, patch

from api_handlers.list_assessments import handler


class TestListAssessmentsHandler:
    @patch("api_handlers.list_assessments.boto3")
    def test_no_params_uses_scan(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.scan.return_value = {"Items": []}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"queryStringParameters": None}
        resp = handler(event, None)
        assert resp["statusCode"] == 200
        mock_table.scan.assert_called_once()

    @patch("api_handlers.list_assessments.boto3")
    def test_with_account_id_uses_query(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.query.return_value = {"Items": []}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"queryStringParameters": {"accountId": "123456789012"}}
        resp = handler(event, None)
        assert resp["statusCode"] == 200
        mock_table.query.assert_called_once()
        call_kwargs = mock_table.query.call_args[1]
        assert call_kwargs["IndexName"] == "accountId-index"

    @patch("api_handlers.list_assessments.boto3")
    def test_limit_capped_at_100(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.scan.return_value = {"Items": []}
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"queryStringParameters": {"limit": "200"}}
        resp = handler(event, None)
        assert resp["statusCode"] == 200
        call_kwargs = mock_table.scan.call_args[1]
        assert call_kwargs["Limit"] == 100

    @patch("api_handlers.list_assessments.boto3")
    def test_invalid_next_token(self, mock_boto3):
        event = {"queryStringParameters": {"nextToken": "not-valid-json"}}
        resp = handler(event, None)
        assert resp["statusCode"] == 400
        assert "Invalid nextToken" in json.loads(resp["body"])["error"]

    @patch("api_handlers.list_assessments.boto3")
    def test_pagination_token_forwarded(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "assessmentId": "a-1",
                    "accountId": "123456789012",
                    "status": "COMPLETED",
                    "createdAt": "2026-01-01",
                }
            ],
            "LastEvaluatedKey": {"assessmentId": "a-1"},
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"queryStringParameters": None}
        resp = handler(event, None)
        body = json.loads(resp["body"])
        assert "nextToken" in body
        assert json.loads(body["nextToken"]) == {"assessmentId": "a-1"}

    @patch("api_handlers.list_assessments.boto3")
    def test_response_format(self, mock_boto3):
        mock_table = MagicMock()
        mock_table.scan.return_value = {
            "Items": [
                {
                    "assessmentId": "a-1",
                    "accountId": "123456789012",
                    "status": "COMPLETED",
                    "createdAt": "2026-01-01",
                    "findingsCount": Decimal(10),
                    "criticalCount": Decimal(2),
                    "highCount": Decimal(3),
                }
            ],
        }
        mock_boto3.resource.return_value.Table.return_value = mock_table

        event = {"queryStringParameters": None}
        resp = handler(event, None)
        body = json.loads(resp["body"])
        assert body["count"] == 1
        item = body["assessments"][0]
        assert item["assessmentId"] == "a-1"
        assert item["findings"]["total"] == 10
        assert item["findings"]["critical"] == 2
