"""Tests for aggregate_findings pure functions."""

from analyzers.aggregate_findings import (
    count_by_severity,
    deduplicate_findings,
    prepare_findings_summary,
)

# --- deduplicate_findings ---


class TestDeduplicateFindings:
    def test_empty_list(self):
        assert deduplicate_findings([]) == []

    def test_no_duplicates(self):
        findings = [
            {"resourceId": "r1", "resourceType": "AWS::S3::Bucket", "title": "Public bucket"},
            {"resourceId": "r2", "resourceType": "AWS::S3::Bucket", "title": "No encryption"},
        ]
        assert len(deduplicate_findings(findings)) == 2

    def test_exact_duplicate_removed(self):
        finding = {"resourceId": "r1", "resourceType": "AWS::S3::Bucket", "title": "Public bucket"}
        assert len(deduplicate_findings([finding, finding.copy()])) == 1

    def test_keeps_first_occurrence(self):
        f1 = {"resourceId": "r1", "resourceType": "t1", "title": "T", "extra": "first"}
        f2 = {"resourceId": "r1", "resourceType": "t1", "title": "T", "extra": "second"}
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0]["extra"] == "first"

    def test_different_resource_same_title_kept(self):
        findings = [
            {"resourceId": "r1", "resourceType": "t1", "title": "Same title"},
            {"resourceId": "r2", "resourceType": "t1", "title": "Same title"},
        ]
        assert len(deduplicate_findings(findings)) == 2

    def test_same_resource_different_title_kept(self):
        findings = [
            {"resourceId": "r1", "resourceType": "t1", "title": "Title A"},
            {"resourceId": "r1", "resourceType": "t1", "title": "Title B"},
        ]
        assert len(deduplicate_findings(findings)) == 2

    def test_missing_fields_treated_as_empty(self):
        findings = [
            {"title": "No resource"},
            {"title": "No resource"},
        ]
        # Both have same key ("", "", "No resource"), so deduped to 1
        assert len(deduplicate_findings(findings)) == 1


# --- count_by_severity ---


class TestCountBySeverity:
    def test_empty(self):
        result = count_by_severity([])
        assert result == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def test_single_finding(self):
        result = count_by_severity([{"severity": "HIGH"}])
        assert result["HIGH"] == 1
        assert result["CRITICAL"] == 0

    def test_mixed_severities(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
            {"severity": "INFO"},
        ]
        result = count_by_severity(findings)
        assert result == {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1}

    def test_unknown_severity_ignored(self):
        result = count_by_severity([{"severity": "UNKNOWN"}])
        assert all(v == 0 for v in result.values())

    def test_lowercase_severity_normalized(self):
        result = count_by_severity([{"severity": "high"}])
        assert result["HIGH"] == 1

    def test_missing_severity_defaults_to_info(self):
        result = count_by_severity([{}])
        assert result["INFO"] == 1


# --- prepare_findings_summary ---


class TestPrepareFindingsSummary:
    def test_empty(self):
        result = prepare_findings_summary([])
        assert result["byCategory"] == {}
        assert result["topIssues"] == []
        assert result["categories"] == []

    def test_groups_by_source_stripping_analyzer(self):
        findings = [
            {"source": "iam-analyzer", "severity": "HIGH", "title": "T1", "resourceType": "IAM"},
            {"source": "iam-analyzer", "severity": "LOW", "title": "T2", "resourceType": "IAM"},
            {"source": "s3-analyzer", "severity": "MEDIUM", "title": "T3", "resourceType": "S3"},
        ]
        result = prepare_findings_summary(findings)
        assert "IAM" in result["byCategory"]
        assert "S3" in result["byCategory"]
        assert len(result["byCategory"]["IAM"]) == 2
        assert len(result["byCategory"]["S3"]) == 1

    def test_top_issues_only_critical_high(self):
        findings = [
            {"source": "test", "severity": "CRITICAL", "title": "C1", "resourceType": "T"},
            {"source": "test", "severity": "HIGH", "title": "H1", "resourceType": "T"},
            {"source": "test", "severity": "MEDIUM", "title": "M1", "resourceType": "T"},
            {"source": "test", "severity": "LOW", "title": "L1", "resourceType": "T"},
        ]
        result = prepare_findings_summary(findings)
        severities = {f["severity"] for f in result["topIssues"]}
        assert severities <= {"CRITICAL", "HIGH"}

    def test_top_issues_capped_at_20(self):
        findings = [
            {"source": "test", "severity": "CRITICAL", "title": f"F{i}", "resourceType": "T"}
            for i in range(30)
        ]
        result = prepare_findings_summary(findings)
        assert len(result["topIssues"]) == 20

    def test_resource_types_unique(self):
        findings = [
            {"source": "test", "severity": "LOW", "title": "T1", "resourceType": "AWS::S3::Bucket"},
            {"source": "test", "severity": "LOW", "title": "T2", "resourceType": "AWS::S3::Bucket"},
            {"source": "test", "severity": "LOW", "title": "T3", "resourceType": "AWS::IAM::User"},
        ]
        result = prepare_findings_summary(findings)
        assert len(result["resourceTypesAffected"]) == 2

    def test_categories_matches_by_category_keys(self):
        findings = [
            {"source": "iam-analyzer", "severity": "LOW", "title": "T", "resourceType": "T"},
            {"source": "s3-analyzer", "severity": "LOW", "title": "T", "resourceType": "T"},
        ]
        result = prepare_findings_summary(findings)
        assert set(result["categories"]) == set(result["byCategory"].keys())
