"""Lambda handler for getting assessment report.

This Lambda generates a pre-signed URL for downloading
the assessment report from S3.
"""

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET", "cloudsecure-reports-dev")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Get assessment report download URL.

    Path parameter: assessmentId
    Query parameters:
        - format: pdf, json, csv (default: pdf)

    Returns:
        Pre-signed URL for downloading the report
    """
    logger.info(f"Received request: {json.dumps(event)}")

    try:
        # Get assessment ID from path parameters
        path_params = event.get("pathParameters", {}) or {}
        assessment_id = path_params.get("assessmentId")

        if not assessment_id:
            return api_response(400, {"error": "Missing assessmentId path parameter"})

        # Get format from query parameters
        query_params = event.get("queryStringParameters", {}) or {}
        report_format = query_params.get("format", "pdf").lower()

        if report_format not in ["pdf", "json", "csv"]:
            return api_response(
                400,
                {
                    "error": "Invalid format. Must be pdf, json, or csv.",
                },
            )

        # Fetch assessment from DynamoDB
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

        # Check if assessment is completed
        if item["status"] != "COMPLETED":
            return api_response(
                400,
                {
                    "error": "Report not available. Assessment is not completed.",
                    "status": item["status"],
                    "progress": item.get("progress", 0),
                },
            )

        # Check if report exists
        report_key = item.get("reportS3Key")
        if not report_key:
            return api_response(
                404,
                {
                    "error": "Report not yet generated for this assessment.",
                    "assessmentId": assessment_id,
                },
            )

        # Generate the report key for requested format
        base_key = report_key.rsplit(".", 1)[0]  # Remove extension
        format_key = f"{base_key}.{report_format}"

        # Generate pre-signed URL
        s3 = boto3.client("s3")

        try:
            # Check if the file exists
            s3.head_object(Bucket=REPORTS_BUCKET, Key=format_key)

            # Generate pre-signed URL (valid for 1 hour)
            presigned_url = s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": REPORTS_BUCKET,
                    "Key": format_key,
                },
                ExpiresIn=3600,
            )

            return api_response(
                200,
                {
                    "assessmentId": assessment_id,
                    "format": report_format,
                    "downloadUrl": presigned_url,
                    "expiresIn": 3600,
                    "fileName": f"cloudsecure-report-{assessment_id[:8]}.{report_format}",
                },
            )

        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return api_response(
                    404,
                    {
                        "error": f"Report in {report_format} format not available.",
                        "availableFormats": ["pdf"],  # Default available
                    },
                )
            raise

    except ClientError as e:
        logger.error(f"AWS error: {e}")
        return api_response(500, {"error": "Failed to retrieve report"})

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
