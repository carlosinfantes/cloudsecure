"""Tests for CLI config module."""

import json
from unittest.mock import MagicMock, patch

from cloudsecure.config import (
    cache_key,
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
    @patch("cloudsecure.config.boto3")
    def test_cached_value_used(self, mock_boto3, mock_get_config, monkeypatch):
        monkeypatch.delenv("CLOUDSECURE_API_ENDPOINT", raising=False)
        mock_boto3.Session.side_effect = Exception("no AWS in unit tests")
        mock_get_config.return_value = {
            "endpoints": {"default:dev:default": "https://cached.example.com/dev"}
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
                "default:dev:default": "https://old.example.com/dev",
                "default:prod:eu-west-1": "https://prod.example.com/prod",
            }
        }
        invalidate_endpoint(env_name="dev", region=None)
        saved = mock_save.call_args[0][0]
        assert "default:dev:default" not in saved["endpoints"]
        assert "default:prod:eu-west-1" in saved["endpoints"]

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

        save_config({"endpoints": {"default:dev:default": "https://test.com"}})
        result = get_config()
        assert result["endpoints"]["default:dev:default"] == "https://test.com"


class TestCacheKeyRoundTrip:
    """resolve and invalidate must agree on the key.

    They did not: invalidate_endpoint left out the profile, so the refresh
    after a connection error never cleared the stale endpoint and the CLI
    kept calling the old API.
    """

    def test_profile_env_and_region_all_take_part(self):
        keys = {
            cache_key(None, "dev", None),
            cache_key("work", "dev", None),
            cache_key(None, "prod", None),
            cache_key(None, "dev", "eu-west-1"),
        }
        assert len(keys) == 4

    @patch("cloudsecure.config.save_config")
    @patch("cloudsecure.config.get_config")
    @patch("cloudsecure.config.boto3")
    def test_invalidate_removes_the_key_resolve_wrote(
        self, mock_boto3, mock_get_config, mock_save
    ):
        mock_cfn = MagicMock()
        mock_cfn.describe_stacks.return_value = {
            "Stacks": [{"Outputs": [{"OutputKey": "ApiEndpoint", "OutputValue": "https://a/dev"}]}]
        }
        mock_boto3.Session.return_value.client.return_value = mock_cfn
        stored = {}
        mock_get_config.return_value = stored

        resolve_api_endpoint(profile="work", region="eu-west-1", env_name="dev")
        assert stored["endpoints"]

        invalidate_endpoint(env_name="dev", region="eu-west-1", profile="work")

        assert stored["endpoints"] == {}
