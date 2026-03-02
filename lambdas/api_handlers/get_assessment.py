"""Lambda handler for getting assessment status and details.

This Lambda retrieves assessment information from DynamoDB
and returns it to the caller.
"""

import json
import logging
import os

# Add shared module to path
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Get assessment details by ID.

    Path parameter: assessmentId

    Returns:
        Assessment details including status, progress, and finding counts
    """
    logger.info(f"Received request: {json.dumps(event)}")

    try:
        # Get assessment ID from path parameters
        path_params = event.get("pathParameters", {}) or {}
        assessment_id = path_params.get("assessmentId")

        if not assessment_id:
            return api_response(400, {"error": "Missing assessmentId path parameter"})

        # Fetch from DynamoDB
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        response = table.get_item(Key={"assessmentId": assessment_id})

        if "Item" not in response:
            return api_response(
                404,
                {
                    "error": "Assessment not found",
                    "assessmentId": assessment_id,
                },
            )

        item = response["Item"]

        # Build response
        result = {
            "assessmentId": item["assessmentId"],
            "accountId": item["accountId"],
            "status": item["status"],
            "progress": item.get("progress", 0),
            "createdAt": item["createdAt"],
            "startedAt": item.get("startedAt"),
            "completedAt": item.get("completedAt"),
            "findings": {
                "total": item.get("findingsCount", 0),
                "critical": item.get("criticalCount", 0),
                "high": item.get("highCount", 0),
                "medium": item.get("mediumCount", 0),
                "low": item.get("lowCount", 0),
                "info": item.get("infoCount", 0),
            },
            "scope": item.get("scope", ["all"]),
            "complianceFrameworks": item.get("complianceFrameworks", []),
        }

        # Include error message if present
        if item.get("errorMessage"):
            result["errorMessage"] = item["errorMessage"]

        # Include report URL if available
        if item.get("reportS3Key"):
            result["reportAvailable"] = True
        else:
            result["reportAvailable"] = False

        return api_response(200, result)

    except ClientError as e:
        logger.error(f"DynamoDB error: {e}")
        return api_response(500, {"error": "Failed to retrieve assessment"})

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
