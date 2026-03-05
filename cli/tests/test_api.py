"""Tests for CloudSecureAPI SigV4 client."""

import json
from unittest.mock import MagicMock, patch

import pytest


class TestCloudSecureAPI:
    @patch("cloudsecure.api.botocore.session.Session")
    def test_init_strips_trailing_slash(self, mock_session_cls):
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_session.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds
        mock_session_cls.return_value = mock_session

        from cloudsecure.api import CloudSecureAPI

        api = CloudSecureAPI("https://api.example.com/dev/", profile="test", region="us-east-1")
        assert api.endpoint == "https://api.example.com/dev"
        assert api.region == "us-east-1"

    @patch("cloudsecure.api.requests.request")
    @patch("cloudsecure.api.botocore.session.Session")
    def test_get_request(self, mock_session_cls, mock_request):
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.access_key = "AKIAIOSFODNN7EXAMPLE"
        mock_creds.secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_creds.token = None
        mock_session.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds
        mock_session_cls.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"assessmentId": "abc"}
        mock_request.return_value = mock_response

        from cloudsecure.api import CloudSecureAPI

        api = CloudSecureAPI("https://api.example.com/dev")
        result = api.get("assessments/abc")

        assert result == {"assessmentId": "abc"}
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args
        assert call_kwargs[1]["method"] == "GET"
        assert call_kwargs[1]["url"] == "https://api.example.com/dev/assessments/abc"
        # Verify SigV4 headers are present
        assert "Authorization" in call_kwargs[1]["headers"]
        assert "AWS4-HMAC-SHA256" in call_kwargs[1]["headers"]["Authorization"]

    @patch("cloudsecure.api.requests.request")
    @patch("cloudsecure.api.botocore.session.Session")
    def test_post_request_with_body(self, mock_session_cls, mock_request):
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.access_key = "AKIAIOSFODNN7EXAMPLE"
        mock_creds.secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_creds.token = None
        mock_session.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds
        mock_session_cls.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"assessmentId": "new-123"}
        mock_request.return_value = mock_response

        from cloudsecure.api import CloudSecureAPI

        api = CloudSecureAPI("https://api.example.com/dev")
        body = {"accountId": "123456789012", "roleArn": "arn:aws:iam::123456789012:role/Test"}
        result = api.post("assessments", body)

        assert result == {"assessmentId": "new-123"}
        call_kwargs = mock_request.call_args
        assert call_kwargs[1]["method"] == "POST"
        assert call_kwargs[1]["data"] == json.dumps(body)

    @patch("cloudsecure.api.requests.request")
    @patch("cloudsecure.api.botocore.session.Session")
    def test_error_response_raises(self, mock_session_cls, mock_request):
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.access_key = "AKIAIOSFODNN7EXAMPLE"
        mock_creds.secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_creds.token = None
        mock_session.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds
        mock_session_cls.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Bad request"}
        mock_response.text = '{"error": "Bad request"}'
        mock_request.return_value = mock_response

        from cloudsecure.api import CloudSecureAPI

        api = CloudSecureAPI("https://api.example.com/dev")

        with pytest.raises(RuntimeError, match="API error"):
            api.get("bad-path")

    @patch("cloudsecure.api.requests.request")
    @patch("cloudsecure.api.botocore.session.Session")
    def test_non_json_response(self, mock_session_cls, mock_request):
        mock_session = MagicMock()
        mock_creds = MagicMock()
        mock_creds.access_key = "AKIAIOSFODNN7EXAMPLE"
        mock_creds.secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_creds.token = None
        mock_session.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds
        mock_session_cls.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("No JSON")
        mock_response.text = "<html>Not JSON</html>"
        mock_request.return_value = mock_response

        from cloudsecure.api import CloudSecureAPI

        api = CloudSecureAPI("https://api.example.com/dev")
        result = api.get("some-path")

        assert result == {"raw": "<html>Not JSON</html>"}
