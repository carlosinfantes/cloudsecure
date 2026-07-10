"""Tests for AI Synthesis pure functions."""

from ai_synthesis.handler import (
    build_analysis_prompt,
    calculate_risk_score,
    categorize_risk,
    generate_fallback_summary,
    parse_ai_response,
)

# --- calculate_risk_score ---


class TestCalculateRiskScore:
    def test_zero_findings(self):
        assert calculate_risk_score({}, 0) == 0

    def test_all_critical(self):
        counts = {"CRITICAL": 10}
        assert calculate_risk_score(counts, 10) == 100

    def test_all_low(self):
        counts = {"LOW": 10}
        # weighted_sum = 2*10 = 20, max = 10*10 = 100, score = 20
        assert calculate_risk_score(counts, 10) == 20

    def test_mixed_severities(self):
        counts = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 5}
        # weighted_sum = 10*2 + 7*3 + 4*5 = 20+21+20 = 61
        # max = 10*10 = 100, score = 61, floored by critical > 0
        assert calculate_risk_score(counts, 10) == 70

    def test_critical_floors_at_70(self):
        counts = {"CRITICAL": 1, "LOW": 99}
        total = 100
        # weighted_sum = 10*1 + 2*99 = 208, max = 1000, score = 20
        # critical > 0 -> max(20, 70) = 70
        assert calculate_risk_score(counts, total) == 70

    def test_many_high_floors_at_50(self):
        counts = {"HIGH": 6, "LOW": 4}
        total = 10
        # weighted_sum = 7*6 + 2*4 = 50, max = 100, score = 50
        # high > 5 -> max(50, 50) = 50
        assert calculate_risk_score(counts, total) == 50

    def test_five_high_no_floor(self):
        counts = {"HIGH": 5}
        # weighted_sum = 7*5 = 35, max = 50, score = 70
        # high is exactly 5, not > 5, no floor
        assert calculate_risk_score(counts, 5) == 70

    def test_capped_at_100(self):
        counts = {"CRITICAL": 100}
        assert calculate_risk_score(counts, 100) == 100

    def test_unknown_severity_ignored(self):
        counts = {"UNKNOWN": 10}
        # weighted_sum = 0, max = 100, score = 0
        assert calculate_risk_score(counts, 10) == 0

    def test_info_severity_zero_weight(self):
        counts = {"INFO": 50}
        assert calculate_risk_score(counts, 50) == 0


# --- categorize_risk ---


class TestCategorizeRisk:
    def test_zero(self):
        assert categorize_risk(0) == "MINIMAL"

    def test_19(self):
        assert categorize_risk(19) == "MINIMAL"

    def test_20(self):
        assert categorize_risk(20) == "LOW"

    def test_39(self):
        assert categorize_risk(39) == "LOW"

    def test_40(self):
        assert categorize_risk(40) == "MEDIUM"

    def test_59(self):
        assert categorize_risk(59) == "MEDIUM"

    def test_60(self):
        assert categorize_risk(60) == "HIGH"

    def test_79(self):
        assert categorize_risk(79) == "HIGH"

    def test_80(self):
        assert categorize_risk(80) == "CRITICAL"

    def test_100(self):
        assert categorize_risk(100) == "CRITICAL"


# --- parse_ai_response ---


class TestParseAiResponse:
    def test_valid_json(self):
        text = '{"executiveSummary": "All good", "keyFindings": ["f1"]}'
        result = parse_ai_response(text)
        assert result["executiveSummary"] == "All good"
        assert result["keyFindings"] == ["f1"]

    def test_json_in_markdown_code_block(self):
        text = '```json\n{"executiveSummary": "test", "keyFindings": []}\n```'
        result = parse_ai_response(text)
        assert result["executiveSummary"] == "test"

    def test_invalid_json_fallback(self):
        text = "This is just plain text with no JSON structure at all. " * 5
        result = parse_ai_response(text)
        assert "executiveSummary" in result
        assert result["keyFindings"] == []
        assert result["patterns"] == []

    def test_short_invalid_json_empty_summary(self):
        result = parse_ai_response("short")
        assert result["executiveSummary"] == ""


# --- generate_fallback_summary ---


class TestGenerateFallbackSummary:
    def test_zero_findings(self):
        result = generate_fallback_summary({}, 0)
        assert "no security findings" in result.lower()

    def test_with_critical(self):
        result = generate_fallback_summary({"CRITICAL": 3}, 10)
        assert "3 critical" in result.lower()

    def test_with_high(self):
        result = generate_fallback_summary({"HIGH": 5}, 10)
        assert "5 high" in result.lower()

    def test_with_critical_and_high(self):
        result = generate_fallback_summary({"CRITICAL": 2, "HIGH": 4}, 10)
        assert "2 critical" in result.lower()
        assert "4 high" in result.lower()

    def test_no_critical_or_high(self):
        result = generate_fallback_summary({"MEDIUM": 5}, 5)
        assert "5 findings" in result
        assert "critical" not in result.lower()


# --- build_analysis_prompt ---


class TestBuildAnalysisPrompt:
    def test_contains_account_id(self):
        prompt = build_analysis_prompt({}, {}, 0, "123456789012")
        assert "123456789012" in prompt

    def test_contains_severity_counts(self):
        counts = {"CRITICAL": 3, "HIGH": 5}
        prompt = build_analysis_prompt({}, counts, 8, "123456789012")
        assert "Critical: 3" in prompt
        assert "High: 5" in prompt

    def test_contains_top_issues(self):
        summary = {
            "topIssues": [
                {"severity": "CRITICAL", "title": "Root MFA disabled", "resourceType": "IAM"}
            ]
        }
        prompt = build_analysis_prompt(summary, {}, 1, "123456789012")
        assert "Root MFA disabled" in prompt

    def test_empty_summary(self):
        prompt = build_analysis_prompt({}, {}, 0, "123456789012")
        assert "No critical or high severity issues found" in prompt
