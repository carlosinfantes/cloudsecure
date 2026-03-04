"""Tests for Prowler finding normalization functions."""

from prowler_scanner.handler import (
    map_resource_type,
    normalize_legacy_finding,
    normalize_ocsf_finding,
    normalize_prowler_finding,
)

ASSESSMENT_ID = "test-assessment-123"
ACCOUNT_ID = "123456789012"


# --- map_resource_type ---


class TestMapResourceType:
    def test_known_types(self):
        assert map_resource_type("AwsIamUser") == "AWS::IAM::User"
        assert map_resource_type("AwsS3Bucket") == "AWS::S3::Bucket"
        assert map_resource_type("AwsEc2SecurityGroup") == "AWS::EC2::SecurityGroup"
        assert map_resource_type("AwsRdsDbInstance") == "AWS::RDS::DBInstance"
        assert map_resource_type("AwsCloudTrailTrail") == "AWS::CloudTrail::Trail"
        assert map_resource_type("AwsAccount") == "AWS::Account"

    def test_unknown_type_fallback(self):
        assert map_resource_type("SomeNewType") == "AWS::SomeNewType"


# --- normalize_legacy_finding ---


class TestNormalizeLegacyFinding:
    def test_pass_returns_none(self):
        finding = {"Status": "PASS", "Severity": "high", "CheckTitle": "Test"}
        assert normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID) is None

    def test_info_returns_none(self):
        finding = {"Status": "INFO"}
        assert normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID) is None

    def test_manual_returns_none(self):
        finding = {"Status": "MANUAL"}
        assert normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID) is None

    def test_fail_returns_normalized(self):
        finding = {
            "Status": "FAIL",
            "Severity": "high",
            "CheckID": "iam_root_mfa_enabled",
            "CheckTitle": "Root MFA not enabled",
            "StatusExtended": "Root account does not have MFA",
            "ResourceId": "root",
            "ResourceArn": "arn:aws:iam::123456789012:root",
            "ResourceType": "AwsIamUser",
            "Region": "us-east-1",
        }
        result = normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is not None
        assert result["severity"] == "HIGH"
        assert result["title"] == "Root MFA not enabled"
        assert result["source"] == "prowler"
        assert result["sourceId"] == "iam_root_mfa_enabled"
        assert result["resourceType"] == "AWS::IAM::User"
        assert result["region"] == "us-east-1"
        assert result["accountId"] == ACCOUNT_ID

    def test_severity_mapping(self):
        for prowler_sev, expected in [
            ("critical", "CRITICAL"),
            ("high", "HIGH"),
            ("medium", "MEDIUM"),
            ("low", "LOW"),
            ("informational", "INFO"),
        ]:
            finding = {"Status": "FAIL", "Severity": prowler_sev}
            result = normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
            assert result["severity"] == expected

    def test_unknown_severity_defaults_medium(self):
        finding = {"Status": "FAIL", "Severity": "unknown"}
        result = normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result["severity"] == "MEDIUM"

    def test_compliance_mappings(self):
        finding = {
            "Status": "FAIL",
            "Severity": "high",
            "Compliance": {
                "CIS": ["1.1", "1.2"],
                "NIST": ["AC-2"],
            },
        }
        result = normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert len(result["complianceFrameworks"]) == 3
        frameworks = {m["framework"] for m in result["complianceFrameworks"]}
        assert frameworks == {"CIS", "NIST"}

    def test_remediation_extracted(self):
        finding = {
            "Status": "FAIL",
            "Severity": "high",
            "Remediation": {
                "Recommendation": {
                    "Text": "Enable MFA",
                    "Url": "https://docs.aws.amazon.com/mfa",
                }
            },
        }
        result = normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result["remediation"]["description"] == "Enable MFA"
        assert result["remediation"]["url"] == "https://docs.aws.amazon.com/mfa"

    def test_empty_resource_arn_becomes_none(self):
        finding = {"Status": "FAIL", "Severity": "low", "ResourceArn": ""}
        result = normalize_legacy_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result["resourceArn"] is None


# --- normalize_ocsf_finding ---


class TestNormalizeOcsfFinding:
    def _make_ocsf_finding(self, **overrides):
        base = {
            "status": "FAIL",
            "status_id": 2,
            "severity_id": 4,
            "finding_info": {
                "uid": "check-123",
                "title": "Test Check",
                "desc": "Description",
            },
            "message": "Detailed message",
            "resources": [
                {
                    "uid": "resource-1",
                    "type": "AwsIamUser",
                    "region": "us-east-1",
                    "cloud": {"account": {"uid": "arn:aws:iam::123456789012:root"}},
                }
            ],
            "remediation": {
                "desc": "Fix it",
                "references": ["https://example.com"],
            },
        }
        base.update(overrides)
        return base

    def test_pass_status_returns_none(self):
        finding = self._make_ocsf_finding(status="PASS", status_id=1)
        assert normalize_ocsf_finding(finding, ASSESSMENT_ID, ACCOUNT_ID) is None

    def test_fail_returns_normalized(self):
        finding = self._make_ocsf_finding()
        result = normalize_ocsf_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is not None
        assert result["severity"] == "HIGH"  # severity_id=4
        assert result["title"] == "Test Check"
        assert result["source"] == "prowler"
        assert result["resourceType"] == "AWS::IAM::User"

    def test_severity_id_mapping(self):
        for sev_id, expected in [
            (0, "INFO"),
            (1, "INFO"),
            (2, "LOW"),
            (3, "MEDIUM"),
            (4, "HIGH"),
            (5, "CRITICAL"),
        ]:
            finding = self._make_ocsf_finding(severity_id=sev_id, status="FAIL", status_id=2)
            result = normalize_ocsf_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
            assert result is not None
            assert result["severity"] == expected

    def test_empty_resources(self):
        finding = self._make_ocsf_finding(resources=[])
        result = normalize_ocsf_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is not None
        assert result["resourceId"] == "unknown"

    def test_remediation_extracted(self):
        finding = self._make_ocsf_finding()
        result = normalize_ocsf_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result["remediation"]["description"] == "Fix it"
        assert result["remediation"]["url"] == "https://example.com"

    def test_compliance_mappings(self):
        finding = self._make_ocsf_finding(
            compliance={"CIS": ["1.1", "1.2"]},
            status="FAIL",
            status_id=2,
        )
        result = normalize_ocsf_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert len(result["complianceFrameworks"]) == 2


# --- normalize_prowler_finding ---


class TestNormalizeProwlerFinding:
    def test_dispatches_to_ocsf_when_status_id_present(self):
        finding = {"status_id": 2, "status": "FAIL", "severity_id": 3, "resources": []}
        result = normalize_prowler_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is not None  # OCSF path taken (FAIL status_id=2)

    def test_dispatches_to_ocsf_when_finding_info_present(self):
        finding = {
            "finding_info": {"title": "Test"},
            "status": "FAIL",
            "severity_id": 3,
            "resources": [],
        }
        result = normalize_prowler_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is not None

    def test_dispatches_to_legacy_when_no_ocsf_fields(self):
        finding = {"Status": "FAIL", "Severity": "high", "CheckTitle": "Legacy Check"}
        result = normalize_prowler_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is not None
        assert result["title"] == "Legacy Check"

    def test_pass_finding_returns_none(self):
        finding = {"Status": "PASS", "Severity": "low"}
        result = normalize_prowler_finding(finding, ASSESSMENT_ID, ACCOUNT_ID)
        assert result is None
