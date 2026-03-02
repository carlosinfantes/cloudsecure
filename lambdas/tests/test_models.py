"""Tests for CloudSecure data models."""

from datetime import datetime, timedelta
from uuid import UUID

from shared.models import (
    Assessment,
    AssessmentStatus,
    ComplianceFramework,
    ComplianceMapping,
    Finding,
    FindingSeverity,
    Remediation,
)


class TestAssessmentStatus:
    """Tests for AssessmentStatus enum."""

    def test_all_statuses_exist(self):
        assert AssessmentStatus.PENDING == "PENDING"
        assert AssessmentStatus.RUNNING == "RUNNING"
        assert AssessmentStatus.COMPLETED == "COMPLETED"
        assert AssessmentStatus.FAILED == "FAILED"


class TestFindingSeverity:
    """Tests for FindingSeverity enum."""

    def test_all_severities_exist(self):
        assert FindingSeverity.CRITICAL == "CRITICAL"
        assert FindingSeverity.HIGH == "HIGH"
        assert FindingSeverity.MEDIUM == "MEDIUM"
        assert FindingSeverity.LOW == "LOW"
        assert FindingSeverity.INFO == "INFO"


class TestComplianceFramework:
    """Tests for ComplianceFramework enum."""

    def test_cis_framework_exists(self):
        assert ComplianceFramework.CIS_AWS_1_4 == "CIS-AWS-1.4"
        assert ComplianceFramework.CIS_AWS_2_0 == "CIS-AWS-2.0"

    def test_other_frameworks_exist(self):
        assert ComplianceFramework.NIST_800_53 == "NIST-800-53"
        assert ComplianceFramework.SOC2 == "SOC2"
        assert ComplianceFramework.GDPR == "GDPR"
        assert ComplianceFramework.ISO_27001 == "ISO-27001"
        assert ComplianceFramework.HIPAA == "HIPAA"


class TestAssessment:
    """Tests for Assessment model."""

    def test_create_minimal_assessment(self, account_id, role_arn, external_id):
        assessment = Assessment(
            account_id=account_id,
            role_arn=role_arn,
            external_id=external_id,
        )
        assert assessment.account_id == account_id
        assert assessment.role_arn == role_arn
        assert assessment.external_id == external_id
        assert assessment.status == AssessmentStatus.PENDING
        assert assessment.progress == 0
        assert isinstance(assessment.assessment_id, UUID)
        assert isinstance(assessment.created_at, datetime)

    def test_to_dynamodb_item(self, account_id, role_arn, external_id):
        assessment = Assessment(
            account_id=account_id,
            role_arn=role_arn,
            external_id=external_id,
        )
        item = assessment.to_dynamodb_item()

        assert item["accountId"] == account_id
        assert item["roleArn"] == role_arn
        assert item["externalId"] == external_id
        assert item["status"] == "PENDING"
        assert item["progress"] == 0
        assert "assessmentId" in item
        assert "createdAt" in item

    def test_from_dynamodb_item(self, dynamodb_assessment_item):
        assessment = Assessment.from_dynamodb_item(dynamodb_assessment_item)

        assert assessment.account_id == dynamodb_assessment_item["accountId"]
        assert assessment.role_arn == dynamodb_assessment_item["roleArn"]
        assert assessment.status == AssessmentStatus.PENDING
        assert assessment.progress == 0

    def test_assessment_with_all_fields(self, account_id, role_arn, external_id):
        now = datetime.utcnow()
        assessment = Assessment(
            account_id=account_id,
            role_arn=role_arn,
            external_id=external_id,
            status=AssessmentStatus.COMPLETED,
            progress=100,
            created_at=now,
            started_at=now,
            completed_at=now + timedelta(minutes=30),
            findings_count=10,
            critical_count=1,
            high_count=2,
            medium_count=3,
            low_count=4,
            info_count=0,
            report_s3_key="reports/123.pdf",
            customer_id="cust-123",
            compliance_frameworks=[ComplianceFramework.CIS_AWS_1_4],
        )

        item = assessment.to_dynamodb_item()
        assert item["status"] == "COMPLETED"
        assert item["progress"] == 100
        assert item["findingsCount"] == 10
        assert item["criticalCount"] == 1
        assert "startedAt" in item
        assert "completedAt" in item
        assert item["reportS3Key"] == "reports/123.pdf"
        assert item["customerId"] == "cust-123"


class TestFinding:
    """Tests for Finding model."""

    def test_create_minimal_finding(self, assessment_id, account_id):
        finding = Finding(
            assessment_id=assessment_id,
            source="prowler",
            severity=FindingSeverity.HIGH,
            title="Test Finding",
            description="Test description",
            resource_type="AWS::S3::Bucket",
            resource_id="test-bucket",
            region="eu-west-1",
            account_id=account_id,
        )

        assert finding.assessment_id == assessment_id
        assert finding.source == "prowler"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.title == "Test Finding"
        assert isinstance(finding.finding_id, UUID)

    def test_finding_with_compliance_mapping(self, assessment_id, account_id):
        finding = Finding(
            assessment_id=assessment_id,
            source="iam-analyzer",
            severity=FindingSeverity.CRITICAL,
            title="MFA not enabled",
            description="User does not have MFA enabled",
            resource_type="AWS::IAM::User",
            resource_id="test-user",
            region="global",
            account_id=account_id,
            compliance_frameworks=[
                ComplianceMapping(
                    framework=ComplianceFramework.CIS_AWS_1_4,
                    control="1.10",
                    description="Ensure MFA is enabled for the root account",
                )
            ],
        )

        assert len(finding.compliance_frameworks) == 1
        assert finding.compliance_frameworks[0].framework == ComplianceFramework.CIS_AWS_1_4
        assert finding.compliance_frameworks[0].control == "1.10"

    def test_finding_with_remediation(self, assessment_id, account_id):
        finding = Finding(
            assessment_id=assessment_id,
            source="s3-analyzer",
            severity=FindingSeverity.MEDIUM,
            title="Public bucket",
            description="S3 bucket is publicly accessible",
            resource_type="AWS::S3::Bucket",
            resource_id="public-bucket",
            region="eu-west-1",
            account_id=account_id,
            remediation=Remediation(
                description="Remove public access from the bucket",
                steps=[
                    "Navigate to S3 console",
                    "Select the bucket",
                    "Remove public access settings",
                ],
                automatable=True,
                effort="LOW",
            ),
        )

        assert finding.remediation is not None
        assert finding.remediation.automatable is True
        assert len(finding.remediation.steps) == 3
