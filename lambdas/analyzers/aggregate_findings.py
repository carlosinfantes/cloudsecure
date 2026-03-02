"""Aggregate Findings Lambda - Collects and stores all analyzer findings.

This Lambda:
1. Receives findings from all analyzers (via Step Functions)
2. Deduplicates findings
3. Stores findings in DynamoDB
4. Updates assessment status and counts
5. Prepares data for AI synthesis
"""

import logging
import os
import sys
from datetime import datetime
from typing import Any
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE", "cloudsecure-findings-dev")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Aggregate findings from all analyzers.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - analyzerResults: List of analyzer results with findings

    Returns:
        dict with aggregation results and summary
    """
    logger.info(f"Aggregating findings for assessment: {event.get('assessmentId')}")

    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    analyzer_results = event.get("analyzerResults", [])

    if not assessment_id:
        return {
            "success": False,
            "error": "Missing assessmentId",
        }

    try:
        dynamodb = boto3.resource("dynamodb")
        assessments_table = dynamodb.Table(ASSESSMENTS_TABLE)
        findings_table = dynamodb.Table(FINDINGS_TABLE)

        # Update assessment progress
        update_assessment_progress(assessments_table, assessment_id, 70)

        # Collect all findings
        all_findings = []
        analyzer_summary = {}

        for result in analyzer_results:
            analyzer_name = result.get("analyzer", "unknown")
            findings = result.get("findings", [])
            success = result.get("success", False)

            analyzer_summary[analyzer_name] = {
                "success": success,
                "findingsCount": len(findings),
                "error": result.get("error"),
            }

            if success:
                all_findings.extend(findings)

        logger.info(
            f"Collected {len(all_findings)} total findings from {len(analyzer_results)} analyzers"
        )

        # Deduplicate findings (by resource + title)
        deduplicated = deduplicate_findings(all_findings)
        logger.info(f"After deduplication: {len(deduplicated)} unique findings")

        # Update assessment progress
        update_assessment_progress(assessments_table, assessment_id, 80)

        # Store findings in DynamoDB
        stored_count = store_findings(findings_table, assessment_id, deduplicated)
        logger.info(f"Stored {stored_count} findings in DynamoDB")

        # Calculate severity counts
        severity_counts = count_by_severity(deduplicated)

        # Update assessment with final counts
        update_assessment_progress(assessments_table, assessment_id, 90)

        update_assessment_counts(
            assessments_table,
            assessment_id,
            total=len(deduplicated),
            critical=severity_counts.get("CRITICAL", 0),
            high=severity_counts.get("HIGH", 0),
            medium=severity_counts.get("MEDIUM", 0),
            low=severity_counts.get("LOW", 0),
            info=severity_counts.get("INFO", 0),
        )

        # Prepare summary for AI synthesis
        findings_summary = prepare_findings_summary(deduplicated)

        return {
            "success": True,
            "assessmentId": assessment_id,
            "accountId": account_id,
            "totalFindings": len(deduplicated),
            "severityCounts": severity_counts,
            "analyzerSummary": analyzer_summary,
            "findingsSummary": findings_summary,
            "storedAt": datetime.utcnow().isoformat(),
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


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate findings based on resource and title.

    Args:
        findings: List of finding dicts

    Returns:
        Deduplicated list of findings
    """
    seen = set()
    unique = []

    for finding in findings:
        # Create dedup key from resource + title
        key = (
            finding.get("resourceId", ""),
            finding.get("resourceType", ""),
            finding.get("title", ""),
        )

        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


def store_findings(table: Any, assessment_id: str, findings: list[dict]) -> int:
    """Store findings in DynamoDB.

    Args:
        table: DynamoDB Table resource
        assessment_id: Assessment ID
        findings: List of finding dicts

    Returns:
        Number of findings stored
    """
    stored = 0

    with table.batch_writer() as batch:
        for finding in findings:
            finding_id = finding.get("findingId", str(uuid4()))

            item = {
                "assessmentId": assessment_id,
                "findingId": finding_id,
                "severity": finding.get("severity", "INFO"),
                "title": finding.get("title", ""),
                "description": finding.get("description", ""),
                "resourceType": finding.get("resourceType", ""),
                "resourceId": finding.get("resourceId", ""),
                "resourceArn": finding.get("resourceArn"),
                "region": finding.get("region", "global"),
                "source": finding.get("source", "unknown"),
                "detectedAt": datetime.utcnow().isoformat(),
            }

            # Remove None values
            item = {k: v for k, v in item.items() if v is not None}

            batch.put_item(Item=item)
            stored += 1

    return stored


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity.

    Args:
        findings: List of finding dicts

    Returns:
        Dict mapping severity to count
    """
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "INFO").upper()
        if severity in counts:
            counts[severity] += 1

    return counts


def prepare_findings_summary(findings: list[dict]) -> dict[str, Any]:
    """Prepare a summary of findings for AI synthesis.

    Args:
        findings: List of finding dicts

    Returns:
        Summary dict for AI processing
    """
    # Group by category (derived from source)
    by_category = {}
    for finding in findings:
        source = finding.get("source", "unknown")
        category = source.replace("-analyzer", "").upper()

        if category not in by_category:
            by_category[category] = []

        by_category[category].append(
            {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "resourceType": finding.get("resourceType"),
            }
        )

    # Group by severity for top issues
    critical_high = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]

    # Get unique resource types affected
    resource_types = list({f.get("resourceType", "") for f in findings})

    return {
        "byCategory": by_category,
        "topIssues": critical_high[:20],  # Top 20 critical/high findings
        "resourceTypesAffected": resource_types,
        "categories": list(by_category.keys()),
    }


def update_assessment_progress(table: Any, assessment_id: str, progress: int) -> None:
    """Update assessment progress.

    Args:
        table: DynamoDB Table resource
        assessment_id: Assessment ID
        progress: Progress percentage
    """
    try:
        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression="SET progress = :progress, updatedAt = :updatedAt",
            ExpressionAttributeValues={
                ":progress": progress,
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except ClientError as e:
        logger.error(f"Failed to update progress: {e}")


def update_assessment_counts(
    table: Any,
    assessment_id: str,
    total: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int,
) -> None:
    """Update assessment finding counts.

    Args:
        table: DynamoDB Table resource
        assessment_id: Assessment ID
        total: Total findings count
        critical: Critical findings count
        high: High findings count
        medium: Medium findings count
        low: Low findings count
        info: Info findings count
    """
    try:
        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression="""
                SET findingsCount = :total,
                    criticalCount = :critical,
                    highCount = :high,
                    mediumCount = :medium,
                    lowCount = :low,
                    infoCount = :info,
                    updatedAt = :updatedAt
            """,
            ExpressionAttributeValues={
                ":total": total,
                ":critical": critical,
                ":high": high,
                ":medium": medium,
                ":low": low,
                ":info": info,
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except ClientError as e:
        logger.error(f"Failed to update counts: {e}")
