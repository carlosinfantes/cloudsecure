"""Tests for AWS client utilities."""

from unittest.mock import MagicMock, patch

from shared.aws_client import (
    get_all_regions,
    get_assumed_role_session,
    get_boto3_client,
    get_default_region,
    validate_role_permissions,
)


class TestGetDefaultRegion:
    """Tests for get_default_region function."""

    def test_returns_env_aws_region(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "us-west-2")
        get_default_region.cache_clear()  # Clear LRU cache
        assert get_default_region() == "us-west-2"

    def test_returns_env_aws_default_region(self, monkeypatch):
        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-1")
        get_default_region.cache_clear()
        assert get_default_region() == "ap-southeast-1"

    def test_returns_fallback_region(self, monkeypatch):
        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        get_default_region.cache_clear()
        assert get_default_region() == "eu-west-1"


class TestGetBoto3Client:
    """Tests for get_boto3_client function."""

    @patch("shared.aws_client.boto3.client")
    def test_creates_client_with_defaults(self, mock_client):
        mock_client.return_value = MagicMock()

        get_boto3_client("s3")

        mock_client.assert_called_once()
        call_kwargs = mock_client.call_args
        assert call_kwargs[0][0] == "s3"

    @patch("shared.aws_client.boto3.client")
    def test_creates_client_with_custom_region(self, mock_client):
        mock_client.return_value = MagicMock()

        get_boto3_client("dynamodb", region_name="us-east-1")

        call_kwargs = mock_client.call_args
        assert call_kwargs[1]["region_name"] == "us-east-1"


class TestGetAssumedRoleSession:
    """Tests for get_assumed_role_session function."""

    @patch("shared.aws_client.get_boto3_client")
    def test_assumes_role_successfully(self, mock_get_client):
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "SessionToken": "FwoGZXIvYXdzEBYaDJ...==",
            }
        }
        mock_get_client.return_value = mock_sts

        get_assumed_role_session(
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            external_id="test-external-id",
            session_name="TestSession",
        )

        mock_sts.assume_role.assert_called_once()
        call_kwargs = mock_sts.assume_role.call_args[1]
        assert call_kwargs["RoleArn"] == "arn:aws:iam::123456789012:role/TestRole"
        assert call_kwargs["ExternalId"] == "test-external-id"
        assert call_kwargs["RoleSessionName"] == "TestSession"


class TestValidateRolePermissions:
    """Tests for validate_role_permissions function."""

    @patch("shared.aws_client.get_assumed_role_session")
    def test_returns_valid_for_successful_assume(self, mock_get_session):
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.client.return_value = mock_sts
        mock_get_session.return_value = mock_session

        result = validate_role_permissions(
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            external_id="test-external-id",
        )

        assert result["valid"] is True
        assert result["account_id"] == "123456789012"
        assert result["error"] is None

    @patch("shared.aws_client.get_assumed_role_session")
    def test_returns_invalid_for_failed_assume(self, mock_get_session):
        mock_get_session.side_effect = Exception("Access denied")

        result = validate_role_permissions(
            role_arn="arn:aws:iam::123456789012:role/InvalidRole",
            external_id="wrong-external-id",
        )

        assert result["valid"] is False
        assert "Access denied" in result["error"]


class TestGetAllRegions:
    """Tests for get_all_regions function."""

    @patch("shared.aws_client.get_boto3_client")
    def test_returns_list_of_regions(self, mock_get_client):
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "eu-west-1"},
                {"RegionName": "ap-northeast-1"},
            ]
        }
        mock_get_client.return_value = mock_ec2

        regions = get_all_regions()

        assert len(regions) == 3
        assert "us-east-1" in regions
        assert "eu-west-1" in regions
        assert "ap-northeast-1" in regions

    def test_uses_provided_session(self):
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-west-2"},
            ]
        }
        mock_session.client.return_value = mock_ec2

        regions = get_all_regions(session=mock_session)

        mock_session.client.assert_called_with("ec2", region_name="us-east-1")
        assert regions == ["us-west-2"]
