"""Tests for the Native Service Puller Lambda."""

from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

from native_service_puller import handler as puller

TABLE_NAME = "test-findings"


def _create_findings_table():
    dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    return dynamodb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "assessmentId", "KeyType": "HASH"},
            {"AttributeName": "findingId", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "assessmentId", "AttributeType": "S"},
            {"AttributeName": "findingId", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _guardduty_finding(index: int) -> dict:
    """A normalized GuardDuty finding: its metadata carries floats."""
    return {
        "assessmentId": "11111111-1111-1111-1111-111111111111",
        "findingId": f"finding-{index:03d}",
        "source": "guardduty",
        "severity": "HIGH",
        "title": f"Threat {index}",
        "description": "desc",
        "resourceType": "AWS::Instance",
        "resourceId": f"i-{index:03d}",
        "region": "eu-west-1",
        "accountId": "123456789012",
        "metadata": {"severityScore": 8.0, "confidence": 5.5},
    }


class TestStoreFindingsInDynamoDb:
    """Regression guards for findings silently lost on write.

    GuardDuty severity and confidence are floats, which the DynamoDB resource
    API rejects; because the rejection happens on a batch_writer flush, only an
    arbitrary subset of the findings used to be written.
    """

    @mock_aws
    def test_stores_every_finding_despite_float_metadata(self, monkeypatch):
        table = _create_findings_table()
        monkeypatch.setattr(puller, "FINDINGS_TABLE", TABLE_NAME)

        findings = [_guardduty_finding(i) for i in range(30)]
        puller.store_findings_in_dynamodb(findings)

        items = table.scan()["Items"]
        assert len(items) == 30

    @mock_aws
    def test_float_metadata_is_stored_as_decimal(self, monkeypatch):
        table = _create_findings_table()
        monkeypatch.setattr(puller, "FINDINGS_TABLE", TABLE_NAME)

        puller.store_findings_in_dynamodb([_guardduty_finding(1)])

        item = table.scan()["Items"][0]
        assert item["metadata"]["severityScore"] == Decimal("8.0")
        assert item["metadata"]["confidence"] == Decimal("5.5")

    @mock_aws
    def test_sets_ttl_so_findings_are_not_kept_forever(self, monkeypatch):
        table = _create_findings_table()
        monkeypatch.setattr(puller, "FINDINGS_TABLE", TABLE_NAME)

        puller.store_findings_in_dynamodb([_guardduty_finding(1)])

        item = table.scan()["Items"][0]
        assert item["expiresAt"] > 0

    @mock_aws
    def test_no_findings_is_a_no_op(self, monkeypatch):
        monkeypatch.setattr(puller, "FINDINGS_TABLE", TABLE_NAME)
        puller.store_findings_in_dynamodb([])  # must not raise without a table


class TestFindingsTableConfiguration:
    def test_table_name_comes_from_the_environment(self, monkeypatch):
        """The Lambda must not silently fall back to the dev table.

        FINDINGS_TABLE was missing from the CDK environment, so every
        deployment wrote its findings to cloudsecure-findings-dev.
        """
        monkeypatch.setenv("FINDINGS_TABLE", "cloudsecure-findings-prod")

        import importlib

        reloaded = importlib.reload(puller)
        try:
            assert reloaded.FINDINGS_TABLE == "cloudsecure-findings-prod"
        finally:
            monkeypatch.delenv("FINDINGS_TABLE")
            importlib.reload(puller)


@pytest.fixture(autouse=True)
def _aws_credentials(monkeypatch):
    """moto must never reach real AWS."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
