"""Placeholder handler for Prowler Scanner Lambda.

This placeholder is used when the Prowler container image build is disabled.
It returns an empty findings list so the assessment pipeline can complete.

TODO: Remove this when Prowler container build is working.
"""

import logging
import os

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def handler(event: dict, context) -> dict:
    """Placeholder handler that returns empty Prowler findings.

    Args:
        event: Step Functions input containing assessment details
        context: Lambda context

    Returns:
        Empty findings response compatible with the assessment pipeline
    """
    logger.warning("Prowler Scanner is disabled - returning empty findings")

    assessment_id = event.get("assessmentId", "unknown")
    account_id = event.get("accountId", "unknown")

    return {
        "success": True,
        "assessmentId": assessment_id,
        "accountId": account_id,
        "analyzer": "prowler",
        "findings": [],
        "findingsCount": 0,
        "disabled": True,
        "message": "Prowler Scanner is temporarily disabled. Other analyzers are still running.",
    }
