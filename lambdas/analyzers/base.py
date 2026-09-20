"""Base analyzer class with common functionality."""

import logging
import os

# Add shared module to path
import sys
from abc import ABC, abstractmethod
from typing import Any, ClassVar
from uuid import UUID

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.aws_client import get_assumed_role_session
from shared.models import ComplianceMapping, Finding, FindingSeverity, Remediation

logger = logging.getLogger()


class BaseAnalyzer(ABC):
    """Base class for security analyzers."""

    #: Analyzer name, used for logging and as the `source` of its findings.
    name: ClassVar[str]

    #: Scope values (CLI `--scope`) this analyzer answers to.
    scopes: ClassVar[tuple[str, ...]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Reject analyzers that forget to declare a name or a scope.

        Without this, a missing or mistyped scope silently excludes the
        analyzer from every scoped assessment.
        """
        super().__init_subclass__(**kwargs)
        if not isinstance(getattr(cls, "name", None), str) or not cls.name:
            raise TypeError(f"{cls.__name__} must define a non-empty 'name' string")
        if not getattr(cls, "scopes", None):
            raise TypeError(f"{cls.__name__} must define a non-empty 'scopes' tuple")

    def __init__(
        self,
        assessment_id: UUID,
        account_id: str,
        session: boto3.Session,
        regions: list[str],
    ):
        self.assessment_id = assessment_id
        self.account_id = account_id
        self.session = session
        self.regions = regions
        self.findings: list[Finding] = []

    @abstractmethod
    def analyze(self) -> list[Finding]:
        """Run the analysis and return findings."""
        pass

    def create_finding(
        self,
        severity: FindingSeverity,
        title: str,
        description: str,
        resource_type: str,
        resource_id: str,
        region: str = "global",
        resource_arn: str | None = None,
        compliance_mappings: list[ComplianceMapping] | None = None,
        remediation: Remediation | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Create a standardized finding."""
        finding = Finding(
            assessment_id=self.assessment_id,
            source=self.name,
            severity=severity,
            title=title,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_arn=resource_arn,
            region=region,
            account_id=self.account_id,
            compliance_frameworks=compliance_mappings or [],
            remediation=remediation,
            metadata=metadata or {},
        )
        self.findings.append(finding)
        return finding

    def get_client(self, service_name: str, region_name: str | None = None) -> Any:
        """Get a boto3 client for the assumed role session."""
        return self.session.client(
            service_name,
            region_name=region_name or "us-east-1",
        )

    def log_info(self, message: str) -> None:
        """Log info message with analyzer context."""
        logger.info(f"[{self.name}] {message}")

    def log_error(self, message: str) -> None:
        """Log error message with analyzer context."""
        logger.error(f"[{self.name}] {message}")

    def log_warning(self, message: str) -> None:
        """Log warning message with analyzer context."""
        logger.warning(f"[{self.name}] {message}")


def run_analyzer(
    analyzer_class: type[BaseAnalyzer],
    event: dict[str, Any],
) -> dict[str, Any]:
    """Common handler logic for running an analyzer.

    Args:
        analyzer_class: The analyzer class to instantiate and run
        event: Step Functions event with assessment details

    Returns:
        dict with analysis results
    """
    assessment_id = event.get("assessmentId")
    account_id = event.get("accountId")
    role_arn = event.get("roleArn")
    external_id = event.get("externalId")
    regions = event.get("regions", ["us-east-1"])
    scope = event.get("scope", ["all"])

    # Skip analyzer if not in requested scope
    analyzer_name = analyzer_class.name
    if "all" not in scope and not any(s in scope for s in analyzer_class.scopes):
        logger.info(f"Skipping {analyzer_name} — not in scope {scope}")
        return {
            "success": True,
            "analyzer": analyzer_name,
            "assessmentId": assessment_id,
            "findingsCount": 0,
            "findings": [],
            "skipped": True,
        }

    logger.info(f"Running {analyzer_class.__name__} for assessment {assessment_id}")

    try:
        # Get assumed role session
        session = get_assumed_role_session(
            role_arn=role_arn,
            external_id=external_id,
            session_name=f"CloudSecure-{analyzer_class.__name__}-{assessment_id[:8]}",
        )

        # Run analyzer
        analyzer = analyzer_class(
            assessment_id=UUID(assessment_id),
            account_id=account_id,
            session=session,
            regions=regions,
        )

        findings = analyzer.analyze()

        # Convert findings to dict for Step Functions
        findings_data = [
            {
                "findingId": str(f.finding_id),
                "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                "title": f.title,
                "description": f.description,
                "resourceType": f.resource_type,
                "resourceId": f.resource_id,
                "resourceArn": f.resource_arn,
                "region": f.region,
            }
            for f in findings
        ]

        return {
            "success": True,
            "analyzer": analyzer.name,
            "assessmentId": assessment_id,
            "findingsCount": len(findings),
            "findings": findings_data,
            "summary": {
                "critical": sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == FindingSeverity.LOW),
                "info": sum(1 for f in findings if f.severity == FindingSeverity.INFO),
            },
        }

    except ClientError as e:
        error_msg = (
            f"AWS API error: {e.response['Error']['Code']} - {e.response['Error']['Message']}"
        )
        logger.error(error_msg)
        return {
            "success": False,
            "analyzer": analyzer_name,
            "assessmentId": assessment_id,
            "error": error_msg,
        }

    except Exception as e:
        logger.exception(f"Analyzer error: {e}")
        return {
            "success": False,
            "analyzer": analyzer_name,
            "assessmentId": assessment_id,
            "error": str(e),
        }
