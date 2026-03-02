"""Lambda handler for listing assessments.

This Lambda retrieves assessments from DynamoDB with optional
filtering by account ID.
"""

import json
import logging
import os
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """List assessments with optional filtering.

    Query parameters:
        - accountId: Filter by AWS account ID
        - limit: Maximum number of results (default 50)
        - nextToken: Pagination token

    Returns:
        List of assessments with pagination
    """
    logger.info(f"Received request: {json.dumps(event)}")

    try:
        # Get query parameters
        query_params = event.get("queryStringParameters", {}) or {}
        account_id = query_params.get("accountId")
        limit = min(int(query_params.get("limit", 50)), 100)
        next_token = query_params.get("nextToken")

        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        # Build scan/query parameters
        scan_kwargs = {
            "Limit": limit,
        }

        if next_token:
            try:
                scan_kwargs["ExclusiveStartKey"] = json.loads(next_token)
            except json.JSONDecodeError:
                return api_response(400, {"error": "Invalid nextToken"})

        # If accountId is provided, use GSI query
        if account_id:
            scan_kwargs["IndexName"] = "accountId-index"
            scan_kwargs["KeyConditionExpression"] = Key("accountId").eq(account_id)
            scan_kwargs["ScanIndexForward"] = False  # Newest first
            response = table.query(**scan_kwargs)
        else:
            # Full table scan (less efficient, but works without account filter)
            response = table.scan(**scan_kwargs)

        # Build response items
        items = []
        for item in response.get("Items", []):
            items.append(
                {
                    "assessmentId": item["assessmentId"],
                    "accountId": item["accountId"],
                    "status": item["status"],
                    "progress": item.get("progress", 0),
                    "createdAt": item["createdAt"],
                    "completedAt": item.get("completedAt"),
                    "findings": {
                        "total": item.get("findingsCount", 0),
                        "critical": item.get("criticalCount", 0),
                        "high": item.get("highCount", 0),
                    },
                }
            )

        result = {
            "assessments": items,
            "count": len(items),
        }

        # Add pagination token if more results exist
        if "LastEvaluatedKey" in response:
            result["nextToken"] = json.dumps(response["LastEvaluatedKey"])

        return api_response(200, result)

    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return api_response(500, {"error": "Failed to list assessments"})

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return api_response(500, {"error": "Internal server error"})


def api_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    """Create API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key",
        },
        "body": json.dumps(body),
    }
