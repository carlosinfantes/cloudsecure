"""AI Synthesis Lambda - Uses Bedrock for intelligent analysis.

This Lambda:
1. Receives findings summary from aggregate_findings
2. Uses Amazon Bedrock (Claude) for:
   - Executive summary generation
   - Finding correlation and patterns
   - Remediation prioritization
   - Risk score calculation
3. Returns AI-enhanced assessment results
"""

import json
import logging
import os
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ASSESSMENTS_TABLE = os.environ.get("ASSESSMENTS_TABLE", "cloudsecure-assessments-dev")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Risk weights by severity
RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 0,
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Generate AI-enhanced analysis of security findings.

    Args:
        event: Step Functions event containing:
            - assessmentId: UUID of the assessment
            - accountId: Target AWS account ID
            - totalFindings: Total finding count
            - severityCounts: Counts by severity
            - findingsSummary: Summary for AI processing

    Returns:
        dict with AI synthesis results
    """
    logger.info(f"Starting AI synthesis for assessment: {event.get('assessmentId')}")

    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    total_findings = event.get("totalFindings", 0)
    severity_counts = event.get("severityCounts", {})
    findings_summary = event.get("findingsSummary", {})

    if not assessment_id:
        return {
            "success": False,
            "error": "Missing assessmentId",
        }

    try:
        # Update assessment progress
        update_assessment_progress(assessment_id, 92)

        # Calculate risk score
        risk_score = calculate_risk_score(severity_counts, total_findings)
        risk_level = categorize_risk(risk_score)

        # Generate AI insights using Bedrock
        ai_insights = generate_ai_insights(
            findings_summary=findings_summary,
            severity_counts=severity_counts,
            total_findings=total_findings,
            account_id=account_id,
        )

        # Update assessment progress
        update_assessment_progress(assessment_id, 95)

        # Store AI results in assessment
        store_ai_results(
            assessment_id=assessment_id,
            risk_score=risk_score,
            risk_level=risk_level,
            ai_insights=ai_insights,
        )

        return {
            "success": True,
            "assessmentId": assessment_id,
            "accountId": account_id,
            "riskScore": risk_score,
            "riskLevel": risk_level,
            "executiveSummary": ai_insights.get("executiveSummary", ""),
            "keyFindings": ai_insights.get("keyFindings", []),
            "remediationPriorities": ai_insights.get("remediationPriorities", []),
            "patterns": ai_insights.get("patterns", []),
            "totalFindings": total_findings,
            "severityCounts": severity_counts,
        }

    except ClientError as e:
        logger.error(f"AWS API error: {e}")
        # Return partial results without AI if Bedrock fails
        risk_score = calculate_risk_score(severity_counts, total_findings)
        return {
            "success": True,  # Partial success
            "assessmentId": assessment_id,
            "accountId": account_id,
            "riskScore": risk_score,
            "riskLevel": categorize_risk(risk_score),
            "executiveSummary": generate_fallback_summary(severity_counts, total_findings),
            "keyFindings": [],
            "remediationPriorities": [],
            "patterns": [],
            "totalFindings": total_findings,
            "severityCounts": severity_counts,
            "aiError": f"Bedrock unavailable: {e.response['Error']['Message']}",
        }

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return {
            "success": False,
            "assessmentId": assessment_id,
            "error": str(e),
        }


def calculate_risk_score(severity_counts: dict[str, int], total_findings: int) -> int:
    """Calculate overall risk score (0-100).

    Args:
        severity_counts: Dict mapping severity to count
        total_findings: Total number of findings

    Returns:
        Risk score from 0-100
    """
    if total_findings == 0:
        return 0

    weighted_sum = sum(
        RISK_WEIGHTS.get(severity, 0) * count for severity, count in severity_counts.items()
    )

    # Normalize to 0-100 scale
    # Max possible is if all findings were critical (weight 10)
    max_possible = total_findings * RISK_WEIGHTS["CRITICAL"]
    score = int((weighted_sum / max_possible) * 100) if max_possible > 0 else 0

    # Boost score based on critical/high presence
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if critical > 0:
        score = max(score, 70)  # Minimum 70 with any critical
    elif high > 5:
        score = max(score, 50)  # Minimum 50 with many high

    return min(score, 100)


def categorize_risk(score: int) -> str:
    """Categorize risk score into levels.

    Args:
        score: Risk score 0-100

    Returns:
        Risk level string
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"


def generate_ai_insights(
    findings_summary: dict[str, Any],
    severity_counts: dict[str, int],
    total_findings: int,
    account_id: str,
) -> dict[str, Any]:
    """Generate AI insights using Amazon Bedrock.

    Args:
        findings_summary: Summary of findings by category
        severity_counts: Counts by severity
        total_findings: Total finding count
        account_id: AWS account ID

    Returns:
        Dict with AI-generated insights
    """
    bedrock = boto3.client("bedrock-runtime", region_name=AWS_REGION)

    # Build the prompt
    prompt = build_analysis_prompt(
        findings_summary=findings_summary,
        severity_counts=severity_counts,
        total_findings=total_findings,
        account_id=account_id,
    )

    try:
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4096,
                    "temperature": 0.3,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt,
                        }
                    ],
                }
            ),
        )

        response_body = json.loads(response["body"].read())
        ai_text = response_body["content"][0]["text"]

        # Parse the structured response
        return parse_ai_response(ai_text)

    except ClientError as e:
        logger.error(f"Bedrock API error: {e}")
        raise


def build_analysis_prompt(
    findings_summary: dict[str, Any],
    severity_counts: dict[str, int],
    total_findings: int,
    account_id: str,
) -> str:
    """Build the analysis prompt for Bedrock.

    Args:
        findings_summary: Summary of findings by category
        severity_counts: Counts by severity
        total_findings: Total finding count
        account_id: AWS account ID

    Returns:
        Formatted prompt string
    """
    categories = findings_summary.get("byCategory", {})
    top_issues = findings_summary.get("topIssues", [])
    resource_types = findings_summary.get("resourceTypesAffected", [])

    # Format top issues for the prompt
    top_issues_text = ""
    for i, issue in enumerate(top_issues[:10], 1):
        top_issues_text += (
            f"{i}. [{issue.get('severity')}] {issue.get('title')} ({issue.get('resourceType')})\n"
        )

    # Format category breakdown
    category_text = ""
    for category, findings in categories.items():
        category_text += f"- {category}: {len(findings)} findings\n"

    prompt = f"""You are a cloud security expert analyzing AWS security assessment findings.

## Assessment Overview
- AWS Account: {account_id}
- Total Findings: {total_findings}
- Critical: {severity_counts.get('CRITICAL', 0)}
- High: {severity_counts.get('HIGH', 0)}
- Medium: {severity_counts.get('MEDIUM', 0)}
- Low: {severity_counts.get('LOW', 0)}
- Informational: {severity_counts.get('INFO', 0)}

## Findings by Category
{category_text}

## Top Critical/High Issues
{top_issues_text if top_issues_text else "No critical or high severity issues found."}

## Resource Types Affected
{', '.join(resource_types[:20]) if resource_types else "None"}

---

Please analyze these findings and provide:

1. **EXECUTIVE_SUMMARY**: A 2-3 paragraph executive summary suitable for leadership, highlighting the overall security posture, key risks, and recommended actions.

2. **KEY_FINDINGS**: List the top 5 most critical findings that need immediate attention, with brief explanations.

3. **PATTERNS**: Identify 3-5 patterns or systemic issues across the findings (e.g., "consistent lack of encryption", "IAM permission sprawl").

4. **REMEDIATION_PRIORITIES**: Provide a prioritized list of 5 remediation actions, starting with the most impactful.

Format your response as JSON with these exact keys:
{{
  "executiveSummary": "...",
  "keyFindings": ["finding1", "finding2", ...],
  "patterns": ["pattern1", "pattern2", ...],
  "remediationPriorities": ["action1", "action2", ...]
}}

Respond ONLY with the JSON object, no additional text."""

    return prompt


def parse_ai_response(ai_text: str) -> dict[str, Any]:
    """Parse the AI response into structured data.

    Args:
        ai_text: Raw AI response text

    Returns:
        Parsed dict with insights
    """
    try:
        # Try to parse as JSON
        # Handle potential markdown code blocks
        text = ai_text.strip()
        if text.startswith("```"):
            # Remove markdown code block
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        return json.loads(text)

    except json.JSONDecodeError:
        logger.warning("Failed to parse AI response as JSON, extracting manually")

        # Fallback: extract what we can
        return {
            "executiveSummary": ai_text[:2000] if len(ai_text) > 100 else "",
            "keyFindings": [],
            "patterns": [],
            "remediationPriorities": [],
        }


def generate_fallback_summary(severity_counts: dict[str, int], total_findings: int) -> str:
    """Generate a basic summary when AI is unavailable.

    Args:
        severity_counts: Counts by severity
        total_findings: Total finding count

    Returns:
        Basic summary text
    """
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)

    if total_findings == 0:
        return "No security findings were identified during this assessment. The AWS account appears to follow security best practices."

    summary = (
        f"This security assessment identified {total_findings} findings across the AWS account. "
    )

    if critical > 0:
        summary += f"Of particular concern are {critical} critical severity issues that require immediate attention. "
    if high > 0:
        summary += f"Additionally, {high} high severity issues were identified that should be addressed promptly. "

    summary += "A detailed review of all findings is recommended to prioritize remediation efforts based on business impact and risk tolerance."

    return summary


def update_assessment_progress(assessment_id: str, progress: int) -> None:
    """Update assessment progress in DynamoDB.

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


def store_ai_results(
    assessment_id: str,
    risk_score: int,
    risk_level: str,
    ai_insights: dict[str, Any],
) -> None:
    """Store AI synthesis results in assessment record.

    Args:
        assessment_id: Assessment ID
        risk_score: Calculated risk score
        risk_level: Risk level category
        ai_insights: AI-generated insights
    """
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(ASSESSMENTS_TABLE)

        table.update_item(
            Key={"assessmentId": assessment_id},
            UpdateExpression="""
                SET riskScore = :riskScore,
                    riskLevel = :riskLevel,
                    executiveSummary = :summary,
                    keyFindings = :keyFindings,
                    remediationPriorities = :priorities,
                    patterns = :patterns,
                    updatedAt = :updatedAt
            """,
            ExpressionAttributeValues={
                ":riskScore": risk_score,
                ":riskLevel": risk_level,
                ":summary": ai_insights.get("executiveSummary", ""),
                ":keyFindings": ai_insights.get("keyFindings", []),
                ":priorities": ai_insights.get("remediationPriorities", []),
                ":patterns": ai_insights.get("patterns", []),
                ":updatedAt": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Failed to store AI results: {e}")
