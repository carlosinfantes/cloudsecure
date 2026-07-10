"""Tests for CLI main module."""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from cloudsecure.main import _get_env_default, cli


class TestVersion:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "cloudsecure" in result.output


class TestGetEnvDefault:
    def test_from_env_var(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY_123", "env_value")
        assert _get_env_default("TEST_KEY_123") == "env_value"

    def test_fallback(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_KEY_XYZ", raising=False)
        assert _get_env_default("NONEXISTENT_KEY_XYZ", "default") == "default"


class TestAssessCommand:
    def test_missing_required_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["assess"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    @patch("cloudsecure.main._with_retry")
    def test_assess_no_wait(self, mock_retry):
        mock_retry.return_value = {"assessmentId": "test-123"}
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "assess",
                "--account-id",
                "123456789012",
                "--role-arn",
                "arn:aws:iam::123456789012:role/Test",
                "--external-id",
                "ext-123",
                "--no-wait",
            ],
        )
        assert result.exit_code == 0
        assert "test-123" in result.output


class TestStatusCommand:
    @patch("cloudsecure.main._with_retry")
    def test_status_list(self, mock_retry):
        mock_retry.return_value = {
            "assessments": [
                {
                    "assessmentId": "a-1",
                    "accountId": "123456789012",
                    "status": "COMPLETED",
                    "createdAt": "2026-01-01",
                }
            ]
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "a-1" in result.output

    @patch("cloudsecure.main._with_retry")
    def test_status_empty(self, mock_retry):
        mock_retry.return_value = {"assessments": []}
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "No assessments found" in result.output

    @patch("cloudsecure.main._with_retry")
    def test_status_single(self, mock_retry):
        mock_retry.return_value = {
            "assessmentId": "a-1",
            "accountId": "123456789012",
            "status": "COMPLETED",
            "createdAt": "2026-01-01",
            "riskScore": 75,
            "riskLevel": "HIGH",
        }
        runner = CliRunner()
        result = runner.invoke(cli, ["status", "a-1"])
        assert result.exit_code == 0
        assert "a-1" in result.output


class TestWithRetry:
    @patch("cloudsecure.main._build_client")
    def test_success_no_retry(self, mock_build):
        from cloudsecure.main import _with_retry

        mock_client = MagicMock()
        mock_client.get.return_value = {"ok": True}
        mock_build.return_value = mock_client

        ctx = MagicMock()
        ctx.obj = {"profile": None, "region": None, "env_name": "dev"}

        result = _with_retry(ctx, lambda c: c.get("test"))
        assert result == {"ok": True}
        mock_build.assert_called_once()

    @patch("cloudsecure.main.invalidate_endpoint")
    @patch("cloudsecure.main._build_client")
    def test_retry_on_connection_error(self, mock_build, mock_invalidate):
        import requests

        from cloudsecure.main import _with_retry

        first_client = MagicMock()
        first_client.get.side_effect = requests.exceptions.ConnectionError("DNS failed")
        second_client = MagicMock()
        second_client.get.return_value = {"ok": True}
        mock_build.side_effect = [first_client, second_client]

        ctx = MagicMock()
        ctx.obj = {"profile": None, "region": None, "env_name": "dev"}

        result = _with_retry(ctx, lambda c: c.get("test"))
        assert result == {"ok": True}
        mock_invalidate.assert_called_once_with(env_name="dev", region=None)
        assert mock_build.call_count == 2
