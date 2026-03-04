"""Shared fixtures for CLI tests."""

import pytest


@pytest.fixture
def mock_api_endpoint():
    return "https://test.execute-api.eu-west-1.amazonaws.com/dev"
