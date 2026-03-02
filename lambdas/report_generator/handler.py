"""Report Generator Lambda - Creates assessment reports in multiple formats.

This Lambda:
1. Retrieves assessment data and findings from DynamoDB
2. Generates reports in requested formats (PDF, HTML, JSON, CSV)
3. Uploads reports to S3
4. Returns pre-signed URLs for download
"""

import csv
import io
import json
import logging
import os
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsecure-findings-dev")
REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET", "cloudsecure-reports-dev")
PRESIGNED_URL_EXPIRY = int(os.environ.get("PRESIGNED_URL_EXPIRY", 3600))  # 1 hour

# Set up Jinja2 template environment
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Generate assessment reports.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - formats: List of formats to generate (pdf, html, json, csv)
            - AI synthesis results (executiveSummary, keyFindings, etc.)

    Returns:
        dict with report URLs and status
    """
    logger.info(f"Generating reports for assessment: {event.get('assessmentId')}")

    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    formats = event.get("formats", ["html", "json", "csv"])

    if not assessment_id:
        return {
            "success": False,
            "error": "Missing assessmentId",
        }

    try:
        # Update assessment progress
        update_assessment_progress(assessment_id, 97)

        # Fetch assessment data
        assessment = get_assessment(assessment_id)
        if not assessment:
            return {
                "success": False,
                "assessmentId": assessment_id,
                "error": "Assessment not found",
            }

        # Fetch all findings
        findings = get_findings(assessment_id)

        # Merge AI synthesis data from event
        assessment["executiveSummary"] = event.get(
            "executiveSummary", assessment.get("executiveSummary", "")
        )
        assessment["keyFindings"] = event.get("keyFindings", assessment.get("keyFindings", []))
        assessment["remediationPriorities"] = event.get(
            "remediationPriorities", assessment.get("remediationPriorities", [])
        )
        assessment["patterns"] = event.get("patterns", assessment.get("patterns", []))
        assessment["riskScore"] = event.get("riskScore", assessment.get("riskScore", 0))
        assessment["riskLevel"] = event.get("riskLevel", assessment.get("riskLevel", "UNKNOWN"))

        # Generate reports
        report_urls = {}
        s3 = boto3.client("s3")

        for fmt in formats:
            try:
                if fmt == "html":
                    content, content_type = generate_html_report(assessment, findings)
                elif fmt == "json":
                    content, content_type = generate_json_report(assessment, findings)
                elif fmt == "csv":
                    content, content_type = generate_csv_report(assessment, findings)
                elif fmt == "pdf":
                    # PDF requires WeasyPrint - will be added in later sprint
                    logger.warning("PDF generation not yet implemented")
                    continue
                else:
                    logger.warning(f"Unknown format: {fmt}")
                    continue

                # Upload to S3
                key = f"assessments/{assessment_id}/report.{fmt}"
                s3.put_object(
                    Bucket=REPORTS_BUCKET,
                    Key=key,
                    Body=content,
                    ContentType=content_type,
                    ServerSideEncryption="aws:kms",
                )

                # Generate pre-signed URL
                url = s3.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": REPORTS_BUCKET, "Key": key},
                    ExpiresIn=PRESIGNED_URL_EXPIRY,
                )

                report_urls[fmt] = url
                logger.info(f"Generated {fmt} report: {key}")

            except Exception as e:
                logger.error(f"Failed to generate {fmt} report: {e}")
                report_urls[fmt] = None

        # Update assessment with report URLs and mark complete
        update_assessment_complete(assessment_id, report_urls)

        return {
            "success": True,
            "assessmentId": assessment_id,
            "accountId": account_id,
            "reportUrls": report_urls,
            "generatedAt": datetime.utcnow().isoformat(),
        }

    except ClientError as e:
        logger.error(f"AWS API error: {e}")
        return {
            "success": False,
            "assessmentId": assessment_id,
            "error": f"AWS API error: {e.response['Error']['Message']}",
        }

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return {
            "success": False,
            "assessmentId": assessment_id,
            "error": str(e),
        }


def get_assessment(assessment_id: str) -> dict[str, Any] | None:
    """Fetch assessment from DynamoDB.

    Args:
        assessment_id: Assessment ID

    Returns:
        Assessment dict or None
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(ASSESSMENTS_TABLE)

    response = table.get_item(Key={"assessmentId": assessment_id})
    return response.get("Item")


def get_findings(assessment_id: str) -> list[dict[str, Any]]:
    """Fetch all findings for an assessment.

    Args:
        assessment_id: Assessment ID

    Returns:
        List of finding dicts
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(FINDINGS_TABLE)

    findings = []
    last_key = None

    while True:
        if last_key:
            response = table.query(
                KeyConditionExpression="assessmentId = :aid",
                ExpressionAttributeValues={":aid": assessment_id},
                ExclusiveStartKey=last_key,
            )
        else:
            response = table.query(
                KeyConditionExpression="assessmentId = :aid",
                ExpressionAttributeValues={":aid": assessment_id},
            )

        findings.extend(response.get("Items", []))

        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "INFO"), 5))

    return findings


def generate_html_report(
    assessment: dict[str, Any],
    findings: list[dict[str, Any]],
) -> tuple[bytes, str]:
    """Generate HTML report.

    Args:
        assessment: Assessment data
        findings: List of findings

    Returns:
        Tuple of (content bytes, content type)
    """
    template = jinja_env.get_template("report.html")

    # Group findings by severity
    findings_by_severity = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": [],
    }
    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity in findings_by_severity:
            findings_by_severity[severity].append(finding)

    # Group findings by category/source
    findings_by_category = {}
    for finding in findings:
        source = finding.get("source", "unknown")
        category = source.replace("-analyzer", "").replace("_", " ").title()
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)

    html = template.render(
        assessment=assessment,
        findings=findings,
        findings_by_severity=findings_by_severity,
        findings_by_category=findings_by_category,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        severity_colors={
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
            "INFO": "#6c757d",
        },
    )

    return html.encode("utf-8"), "text/html; charset=utf-8"


def generate_json_report(
    assessment: dict[str, Any],
    findings: list[dict[str, Any]],
) -> tuple[bytes, str]:
    """Generate JSON report.

    Args:
        assessment: Assessment data
        findings: List of findings

    Returns:
        Tuple of (content bytes, content type)
    """
    report = {
        "metadata": {
            "assessmentId": assessment.get("assessmentId"),
            "accountId": assessment.get("accountId"),
            "status": assessment.get("status"),
            "startedAt": assessment.get("startedAt"),
            "completedAt": datetime.utcnow().isoformat(),
            "generatedAt": datetime.utcnow().isoformat(),
        },
        "summary": {
            "riskScore": assessment.get("riskScore", 0),
            "riskLevel": assessment.get("riskLevel", "UNKNOWN"),
            "totalFindings": assessment.get("findingsCount", len(findings)),
            "severityCounts": {
                "critical": assessment.get("criticalCount", 0),
                "high": assessment.get("highCount", 0),
                "medium": assessment.get("mediumCount", 0),
                "low": assessment.get("lowCount", 0),
                "info": assessment.get("infoCount", 0),
            },
        },
        "executiveSummary": assessment.get("executiveSummary", ""),
        "keyFindings": assessment.get("keyFindings", []),
        "patterns": assessment.get("patterns", []),
        "remediationPriorities": assessment.get("remediationPriorities", []),
        "findings": findings,
    }

    return json.dumps(report, indent=2, default=str).encode("utf-8"), "application/json"


def generate_csv_report(
    assessment: dict[str, Any],
    findings: list[dict[str, Any]],
) -> tuple[bytes, str]:
    """Generate CSV report of findings.

    Args:
        assessment: Assessment data
        findings: List of findings

    Returns:
        Tuple of (content bytes, content type)
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(
        [
            "Finding ID",
            "Severity",
            "Title",
            "Description",
            "Resource Type",
            "Resource ID",
            "Resource ARN",
            "Region",
            "Source",
            "Detected At",
        ]
    )

    # Data rows
    for finding in findings:
        writer.writerow(
            [
                finding.get("findingId", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("resourceType", ""),
                finding.get("resourceId", ""),
                finding.get("resourceArn", ""),
                finding.get("region", ""),
                finding.get("source", ""),
                finding.get("detectedAt", ""),
            ]
        )

    return output.getvalue().encode("utf-8"), "text/csv; charset=utf-8"


def update_assessment_progress(assessment_id: str, progress: int) -> None:
    """Update assessment progress.

    Args:
        assessment_id: Assessment ID
        progress: Progress percentage
    """
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression="SET progress = :progress, updatedAt = :updatedAt",
            ExpressionAttributeValues={
                ":progress": progress,
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Failed to update progress: {e}")


def update_assessment_complete(assessment_id: str, report_urls: dict[str, str]) -> None:
    """Mark assessment as complete with report URLs.

    Args:
        assessment_id: Assessment ID
        report_urls: Dict of format to URL
    """
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression="""
                SET #status = :status,
                    progress = :progress,
                    reportUrls = :reportUrls,
                    completedAt = :completedAt,
                    updatedAt = :updatedAt
            """,
            ExpressionAttributeNames={
                "#status": "status",
            },
            ExpressionAttributeValues={
                ":status": "COMPLETED",
                ":progress": 100,
                ":reportUrls": report_urls,
                ":completedAt": datetime.utcnow().isoformat(),
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Failed to update assessment complete: {e}")
