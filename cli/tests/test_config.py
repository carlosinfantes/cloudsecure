"""Tests for CLI config module."""

import json
from unittest.mock import MagicMock, patch

from cloudsecure.config import (
    get_config,
    invalidate_endpoint,
    resolve_api_endpoint,
    save_config,
)


class TestResolveApiEndpoint:
    def test_env_var_takes_priority(self, monkeypatch):
        monkeypatch.setenv("CLOUDSECURE_API_ENDPOINT", "https://env-var.example.com/dev")
        result = resolve_api_endpoint()
        assert result == "https://env-var.example.com/dev"

    def test_env_var_trailing_slash_stripped(self, monkeypatch):
        monkeypatch.setenv("CLOUDSECURE_API_ENDPOINT", "https://env-var.example.com/dev/")
        result = resolve_api_endpoint()
        assert result == "https://env-var.example.com/dev"

    @patch("cloudsecure.config.get_config")
    def test_cached_value_used(self, mock_get_config, monkeypatch):
        monkeypatch.delenv("CLOUDSECURE_API_ENDPOINT", raising=False)
        mock_get_config.return_value = {
            "endpoints": {"dev:default": "https://cached.example.com/dev"}
        }
        result = resolve_api_endpoint(env_name="dev")
        assert result == "https://cached.example.com/dev"

    @patch("cloudsecure.config.save_config")
    @patch("cloudsecure.config.get_config")
    @patch("cloudsecure.config.boto3")
    def test_cfn_fallback_and_caches(self, mock_boto3, mock_get_config, mock_save, monkeypatch):
        monkeypatch.delenv("CLOUDSECURE_API_ENDPOINT", raising=False)
        mock_get_config.return_value = {}

        mock_cfn = MagicMock()
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [
                {
                    "Outputs": [
                        {"OutputKey": "ApiEndpoint", "OutputValue": "https://cfn.example.com/dev/"}
                    ]
                }
            ]
        }
        mock_boto3.Session.return_value.client.return_value = mock_cfn

        result = resolve_api_endpoint(profile="test", env_name="dev")
        assert result == "https://cfn.example.com/dev"
        mock_save.assert_called_once()

    @patch("cloudsecure.config.get_config")
    @patch("cloudsecure.config.boto3")
    def test_cfn_not_found_raises(self, mock_boto3, mock_get_config, monkeypatch):
        import pytest

        monkeypatch.delenv("CLOUDSECURE_API_ENDPOINT", raising=False)
        mock_get_config.return_value = {}

        mock_cfn = MagicMock()
        mock_cfn.describe_stacks.side_effect = Exception("Stack not found")
        mock_boto3.Session.return_value.client.return_value = mock_cfn

        with pytest.raises(RuntimeError, match="Could not resolve API endpoint"):
            resolve_api_endpoint(profile="test", env_name="dev")


class TestInvalidateEndpoint:
    @patch("cloudsecure.config.save_config")
    @patch("cloudsecure.config.get_config")
    def test_removes_cached_key(self, mock_get_config, mock_save):
        mock_get_config.return_value = {
            "endpoints": {
                "dev:default": "https://old.example.com/dev",
                "prod:eu-west-1": "https://prod.example.com/prod",
            }
        }
        invalidate_endpoint(env_name="dev", region=None)
        saved = mock_save.call_args[0][0]
        assert "dev:default" not in saved["endpoints"]
        assert "prod:eu-west-1" in saved["endpoints"]

    @patch("cloudsecure.config.save_config")
    @patch("cloudsecure.config.get_config")
    def test_noop_if_key_not_present(self, mock_get_config, mock_save):
        mock_get_config.return_value = {"endpoints": {}}
        invalidate_endpoint(env_name="dev")
        mock_save.assert_not_called()


class TestGetAndSaveConfig:
    def test_get_config_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudsecure.config.CONFIG_FILE", tmp_path / "nonexistent.json")
        assert get_config() == {}

    def test_save_and_get_config(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        monkeypatch.setattr("cloudsecure.config.CONFIG_FILE", config_file)
        monkeypatch.setattr("cloudsecure.config.CONFIG_DIR", tmp_path)

        save_config({"endpoints": {"dev:default": "https://test.com"}})
        result = get_config()
        assert result["endpoints"]["dev:default"] == "https://test.com"
