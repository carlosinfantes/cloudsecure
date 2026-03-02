"""Lambda handler for starting a new security assessment.

This Lambda:
1. Validates the request payload
2. Creates an assessment record in DynamoDB
3. Starts the Step Functions state machine execution
4. Returns the assessment ID and execution ARN
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

from shared.models import Assessment, AssessmentStatus, ComplianceFramework

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")
STATE_MACHINE_ARN = os.environ.get("STATE_MACHINE_ARN", "")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Start a new security assessment.

    API Gateway event with body:
    {
        "accountId": "123456789012",
        "roleArn": "arn:aws:iam::123456789012:role/CloudSecureReadOnly",
        "externalId": "unique-external-id",
        "customerId": "optional-customer-id",
        "scope": ["all"],  // optional: specific services to assess
        "complianceFrameworks": ["CIS-AWS-1.4"]  // optional
    }

    Returns:
        API Gateway response with assessment details
    """
    logger.info(f"Received request: {json.dumps(event)}")

    try:
        # Parse request body
        body = json.loads(event.get("body", "{}"))

        # Validate required fields
        required_fields = ["accountId", "roleArn", "externalId"]
        missing_fields = [f for f in required_fields if not body.get(f)]

        if missing_fields:
            return api_response(
                400,
                {
                    "error": "Missing required fields",
                    "missingFields": missing_fields,
                },
            )

        # Validate accountId format
        account_id = body["accountId"]
        if not account_id.isdigit() or len(account_id) != 12:
            return api_response(
                400,
                {
                    "error": "Invalid accountId format. Must be 12-digit AWS account ID.",
                },
            )

        # Validate roleArn format
        role_arn = body["roleArn"]
        if not role_arn.startswith("arn:aws:iam::") or ":role/" not in role_arn:
            return api_response(
                400,
                {
                    "error": "Invalid roleArn format. Must be a valid IAM role ARN.",
                },
            )

        # Parse optional fields
        external_id = body["externalId"]
        customer_id = body.get("customerId")
        scope = body.get("scope", ["all"])
        compliance_frameworks = []

        for fw in body.get("complianceFrameworks", []):
            try:
                compliance_frameworks.append(ComplianceFramework(fw))
            except ValueError:
                return api_response(
                    400,
                    {
                        "error": f"Invalid compliance framework: {fw}",
                        "validFrameworks": [f.value for f in ComplianceFramework],
                    },
                )

        # Create assessment record
        assessment = Assessment(
            account_id=account_id,
            role_arn=role_arn,
            external_id=external_id,
            customer_id=customer_id,
            scope=scope,
            compliance_frameworks=compliance_frameworks,
            status=AssessmentStatus.PENDING,
        )

        # Save to DynamoDB
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        table.put_item(Item=assessment.to_dynamodb_item())
        logger.info(f"Created assessment: {assessment.assessment_id}")

        # Start Step Functions execution
        execution_arn = None
        if STATE_MACHINE_ARN:
            sfn = boto3.client("stepfunctions")

            execution_input = {
                "assessmentId": str(assessment.assessment_id),
                "accountId": account_id,
                "roleArn": role_arn,
                "externalId": external_id,
            }

            try:
                execution = sfn.start_execution(
                    stateMachineArn=STATE_MACHINE_ARN,
                    name=f"assessment-{assessment.assessment_id}",
                    input=json.dumps(execution_input),
                )
                execution_arn = execution["executionArn"]
                logger.info(f"Started execution: {execution_arn}")

            except ClientError as e:
                logger.error(f"Failed to start Step Functions execution: {e}")
                # Update assessment as failed
                table.update_item(
                    Key={"assessmentId": str(assessment.assessment_id)},
                    UpdateExpression="SET #status = :status, errorMessage = :error",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":status": AssessmentStatus.FAILED.value,
                        ":error": f"Failed to start execution: {str(e)}",
                    },
                )
                return api_response(
                    500,
                    {
                        "error": "Failed to start assessment execution",
                        "assessmentId": str(assessment.assessment_id),
                    },
                )

        return api_response(
            201,
            {
                "assessmentId": str(assessment.assessment_id),
                "accountId": account_id,
                "status": assessment.status.value,
                "createdAt": assessment.created_at.isoformat(),
                "executionArn": execution_arn,
                "message": "Assessment started successfully",
            },
        )

    except json.JSONDecodeError:
        return api_response(400, {"error": "Invalid JSON in request body"})

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
