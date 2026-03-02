"""Core data models for CloudSecure assessments and findings."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AssessmentStatus(str, Enum):
    """Assessment lifecycle status."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingSeverity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    CIS_AWS_1_4 = "CIS-AWS-1.4"
    CIS_AWS_2_0 = "CIS-AWS-2.0"
    NIST_800_53 = "NIST-800-53"
    SOC2 = "SOC2"
    GDPR = "GDPR"
    ISO_27001 = "ISO-27001"
    HIPAA = "HIPAA"


class ComplianceMapping(BaseModel):
    """Compliance framework control mapping."""

    framework: ComplianceFramework
    control: str
    description: str | None = None


class Remediation(BaseModel):
    """Remediation guidance for a finding."""

    description: str
    steps: list[str] = Field(default_factory=list)
    automatable: bool = False
    effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH


class Evidence(BaseModel):
    """Evidence for a finding."""

    current: str
    expected: str


class AIEnhancement(BaseModel):
    """AI-generated enhancements for a finding."""

    risk_context: str | None = None
    business_impact: str | None = None
    correlated_findings: list[str] = Field(default_factory=list)
    priority_score: int = Field(ge=0, le=100, default=50)


class Finding(BaseModel):
    """Security finding from an assessment."""

    finding_id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    source: str  # prowler, iam-analyzer, securityhub, etc.
    source_id: str | None = None
    severity: FindingSeverity
    title: str
    description: str
    resource_type: str  # AWS::EC2::SecurityGroup, AWS::S3::Bucket, etc.
    resource_arn: str | None = None
    resource_id: str
    region: str
    account_id: str
    compliance_frameworks: list[ComplianceMapping] = Field(default_factory=list)
    remediation: Remediation | None = None
    evidence: Evidence | None = None
    ai_enhanced: AIEnhancement | None = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class Assessment(BaseModel):
    """Security assessment record."""

    assessment_id: UUID = Field(default_factory=uuid4)
    account_id: str
    role_arn: str
    external_id: str
    status: AssessmentStatus = AssessmentStatus.PENDING
    progress: int = Field(ge=0, le=100, default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    report_s3_key: str | None = None
    error_message: str | None = None
    scope: list[str] = Field(default_factory=lambda: ["all"])
    compliance_frameworks: list[ComplianceFramework] = Field(default_factory=list)
    customer_id: str | None = None  # Links to CRF context

    class Config:
        use_enum_values = True

    def to_dynamodb_item(self) -> dict[str, Any]:
        """Convert to DynamoDB item format."""
        item = {
            "assessmentId": str(self.assessment_id),
            "accountId": self.account_id,
            "roleArn": self.role_arn,
            "externalId": self.external_id,
            "status": self.status,
            "progress": self.progress,
            "createdAt": self.created_at.isoformat(),
            "findingsCount": self.findings_count,
            "criticalCount": self.critical_count,
            "highCount": self.high_count,
            "mediumCount": self.medium_count,
            "lowCount": self.low_count,
            "infoCount": self.info_count,
            "scope": self.scope,
            "complianceFrameworks": self.compliance_frameworks,
        }
        if self.started_at:
            item["startedAt"] = self.started_at.isoformat()
        if self.completed_at:
            item["completedAt"] = self.completed_at.isoformat()
        if self.report_s3_key:
            item["reportS3Key"] = self.report_s3_key
        if self.error_message:
            item["errorMessage"] = self.error_message
        if self.customer_id:
            item["customerId"] = self.customer_id
        return item

    @classmethod
    def from_dynamodb_item(cls, item: dict[str, Any]) -> "Assessment":
        """Create from DynamoDB item."""
        return cls(
            assessment_id=UUID(item["assessmentId"]),
            account_id=item["accountId"],
            role_arn=item["roleArn"],
            external_id=item["externalId"],
            status=AssessmentStatus(item["status"]),
            progress=item.get("progress", 0),
            created_at=datetime.fromisoformat(item["createdAt"]),
            started_at=(
                datetime.fromisoformat(item["startedAt"]) if item.get("startedAt") else None
            ),
            completed_at=(
                datetime.fromisoformat(item["completedAt"]) if item.get("completedAt") else None
            ),
            findings_count=item.get("findingsCount", 0),
            critical_count=item.get("criticalCount", 0),
            high_count=item.get("highCount", 0),
            medium_count=item.get("mediumCount", 0),
            low_count=item.get("lowCount", 0),
            info_count=item.get("infoCount", 0),
            report_s3_key=item.get("reportS3Key"),
            error_message=item.get("errorMessage"),
            scope=item.get("scope", ["all"]),
            compliance_frameworks=[
                ComplianceFramework(f) for f in item.get("complianceFrameworks", [])
            ],
            customer_id=item.get("customerId"),
        )
