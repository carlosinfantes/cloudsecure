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


def cache_key(profile: str | None, env_name: str, region: str | None) -> str:
    """Key under which an endpoint is cached.

    An endpoint belongs to one profile, environment and region, so all three
    identify it. Both the reader and the invalidator must build the key the
    same way, or the cache can never be cleared.
    """
    return f"{profile or 'default'}:{env_name}:{region or 'default'}"


def resolve_api_endpoint(profile: str | None = None, region: str | None = None,
                         env_name: str = "dev") -> str:
    """Resolve the API Gateway endpoint URL.

    Priority:
    1. CLOUDSECURE_API_ENDPOINT environment variable
    2. CloudFormation stack outputs (live lookup, always fresh)
    3. Cached value in ~/.cloudsecure/config.json (fallback)
    """
    # Check env var
    endpoint = os.environ.get("CLOUDSECURE_API_ENDPOINT")
    if endpoint:
        return endpoint.rstrip("/")

    config = get_config()
    key = cache_key(profile, env_name, region)

    # Query CloudFormation (live, always fresh)
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        cfn = session.client("cloudformation")
        stack_name = f"CloudSecure-API-{env_name}"
        response = cfn.describe_stacks(StackName=stack_name)
        outputs = response["Stacks"][0].get("Outputs", [])

        for output in outputs:
            if output["OutputKey"] == "ApiEndpoint":
                endpoint = output["OutputValue"].rstrip("/")
                config.setdefault("endpoints", {})[key] = endpoint
                save_config(config)
                return endpoint
    except Exception:
        pass

    # Fall back to cache (e.g. when offline or lacking CFN permissions)
    cached = config.get("endpoints", {}).get(key)
    if cached:
        return cached

    raise RuntimeError(
        "Could not resolve API endpoint. Deploy CloudSecure first or set "
        "CLOUDSECURE_API_ENDPOINT environment variable."
    )


def invalidate_endpoint(
    env_name: str = "dev",
    region: str | None = None,
    profile: str | None = None,
) -> None:
    """Remove a cached endpoint so the next resolve fetches from CloudFormation."""
    config = get_config()
    key = cache_key(profile, env_name, region)
    endpoints = config.get("endpoints", {})
    if key in endpoints:
        del endpoints[key]
        save_config(config)
