"""Configuration management for CloudSecure CLI."""

import json
import os
from pathlib import Path

import boto3


CONFIG_DIR = Path.home() / ".cloudsecure"
CONFIG_FILE = CONFIG_DIR / "config.json"


def get_config() -> dict:
    """Load cached configuration."""
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config: dict) -> None:
    """Save configuration to cache file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def resolve_api_endpoint(profile: str | None = None, region: str | None = None,
                         env_name: str = "dev") -> str:
    """Resolve the API Gateway endpoint URL.

    Priority:
    1. CLOUDSECURE_API_ENDPOINT environment variable
    2. Cached value in ~/.cloudsecure/config.json
    3. Query CloudFormation stack outputs
    """
    # Check env var
    endpoint = os.environ.get("CLOUDSECURE_API_ENDPOINT")
    if endpoint:
        return endpoint.rstrip("/")

    # Check cache
    config = get_config()
    cache_key = f"{env_name}:{region or 'default'}"
    cached = config.get("endpoints", {}).get(cache_key)
    if cached:
        return cached

    # Query CloudFormation
    session = boto3.Session(profile_name=profile, region_name=region)
    cfn = session.client("cloudformation")
    stack_name = f"CloudSecure-API-{env_name}"

    try:
        response = cfn.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0].get("Outputs", [])

        for output in outputs:
            if output["OutputKey"] == "ApiEndpoint":
                endpoint = output["OutputValue"].rstrip("/")
                # Cache it
                config.setdefault("endpoints", {})[cache_key] = endpoint
                save_config(config)
                return endpoint
    except Exception:
        pass

    raise RuntimeError(
        f"Could not resolve API endpoint. Deploy CloudSecure first or set "
        f"CLOUDSECURE_API_ENDPOINT environment variable."
    )


def invalidate_endpoint(env_name: str = "dev", region: str | None = None) -> None:
    """Remove a cached endpoint so the next resolve fetches from CloudFormation."""
    config = get_config()
    cache_key = f"{env_name}:{region or 'default'}"
    endpoints = config.get("endpoints", {})
    if cache_key in endpoints:
        del endpoints[cache_key]
        save_config(config)
