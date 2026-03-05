"""Pytest configuration and fixtures for CloudSecure tests."""

import os
import sys
from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

import boto3
import pytest

# Add lambdas directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Set AWS region for tests
os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
os.environ["AWS_REGION"] = "eu-west-1"
# Prevent real AWS calls from moto tests
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
os.environ["AWS_SECURITY_TOKEN"] = "testing"
os.environ["AWS_SESSION_TOKEN"] = "testing"


@pytest.fixture
def assessment_id():
    """Generate a test assessment ID."""
    return uuid4()


@pytest.fixture
def account_id():
    """Test AWS account ID."""
    return "123456789012"


@pytest.fixture
def role_arn(account_id):
    """Test IAM role ARN."""
    return f"arn:aws:iam::{account_id}:role/CloudSecureReadOnly"


@pytest.fixture
def external_id():
    """Test external ID."""
    return "test-external-id-12345"


@pytest.fixture
def sample_event(assessment_id, account_id, role_arn, external_id):
    """Sample Lambda event for testing."""
    return {
        "assessmentId": str(assessment_id),
        "accountId": account_id,
        "roleArn": role_arn,
        "externalId": external_id,
    }


@pytest.fixture
def dynamodb_assessment_item(assessment_id, account_id, role_arn, external_id):
    """Sample DynamoDB assessment item."""
    return {
        "assessmentId": str(assessment_id),
        "accountId": account_id,
        "roleArn": role_arn,
        "externalId": external_id,
        "status": "PENDING",
        "progress": 0,
        "createdAt": datetime.utcnow().isoformat(),
        "findingsCount": 0,
        "criticalCount": 0,
        "highCount": 0,
        "mediumCount": 0,
        "lowCount": 0,
        "infoCount": 0,
        "scope": ["all"],
        "complianceFrameworks": [],
    }


@pytest.fixture
def mock_boto3_session():
    """A MagicMock boto3.Session for analyzer tests."""
    return MagicMock(spec=boto3.Session)
