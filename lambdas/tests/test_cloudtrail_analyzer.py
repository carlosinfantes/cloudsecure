"""Tests for CloudTrail Analyzer."""

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

from analyzers.cloudtrail_analyzer import CloudTrailAnalyzer, handler
from shared.models import FindingSeverity


def _make_analyzer(mock_session=None):
    session = mock_session or MagicMock()
    return CloudTrailAnalyzer(
        assessment_id=uuid4(),
        account_id="123456789012",
        session=session,
        regions=["us-east-1"],
    )


class TestCloudTrailAnalyzerTrails:
    def test_no_trails_configured(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {"trailList": []}

        analyzer._check_trails(mock_ct)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.CRITICAL
        assert "No CloudTrail trails" in analyzer.findings[0].title

    def test_trail_without_log_validation(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "main-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": False,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            ]
        }
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}

        analyzer._check_trails(mock_ct)

        findings_titles = [f.title for f in analyzer.findings]
        assert any("log file validation" in t for t in findings_titles)

    def test_trail_without_kms(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "main-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                }
            ]
        }
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}

        analyzer._check_trails(mock_ct)

        findings_titles = [f.title for f in analyzer.findings]
        assert any("KMS" in t for t in findings_titles)

    def test_trail_not_logging(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "stopped-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/stopped-trail",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            ]
        }
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": False}

        analyzer._check_trails(mock_ct)

        assert any(f.severity == FindingSeverity.CRITICAL for f in analyzer.findings)
        assert any("not currently logging" in f.title for f in analyzer.findings)

    def test_no_multi_region_trail(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "single-region",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/single",
                    "IsMultiRegionTrail": False,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "key-id",
                }
            ]
        }
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}

        analyzer._check_trails(mock_ct)

        assert any("multi-region" in f.title for f in analyzer.findings)

    def test_no_management_events(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "data-only",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/data",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "key-id",
                }
            ]
        }
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": False}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}

        analyzer._check_trails(mock_ct)

        assert any("management events" in f.title for f in analyzer.findings)

    def test_fully_compliant_trail(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "good-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/good",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            ]
        }
        mock_ct.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True}]
        }
        mock_ct.get_trail_status.return_value = {"IsLogging": True}

        analyzer._check_trails(mock_ct)

        assert len(analyzer.findings) == 0


class TestCloudTrailAnalyzerRootUsage:
    def test_root_usage_detected(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.lookup_events.return_value = {
            "Events": [
                {
                    "EventName": "ConsoleLogin",
                    "CloudTrailEvent": json.dumps({"userIdentity": {"type": "Root"}}),
                },
                {
                    "EventName": "StopInstances",
                    "CloudTrailEvent": json.dumps({"userIdentity": {"type": "Root"}}),
                },
            ]
        }

        analyzer._check_root_usage(mock_ct)

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "2 times" in analyzer.findings[0].title

    def test_no_root_usage(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.lookup_events.return_value = {"Events": []}

        analyzer._check_root_usage(mock_ct)

        assert len(analyzer.findings) == 0

    def test_assumed_root_events_filtered(self):
        analyzer = _make_analyzer()
        mock_ct = MagicMock()
        mock_ct.lookup_events.return_value = {
            "Events": [
                {
                    "EventName": "OrgAction",
                    "CloudTrailEvent": json.dumps(
                        {
                            "userIdentity": {
                                "type": "Root",
                                "sessionContext": {"assumedRoot": "true"},
                            }
                        }
                    ),
                },
            ]
        }

        analyzer._check_root_usage(mock_ct)

        assert len(analyzer.findings) == 0


class TestCloudTrailAnalyzerMetricFilters:
    def test_no_cloudtrail_log_groups(self):
        analyzer = _make_analyzer()
        mock_logs = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"logGroups": [{"logGroupName": "/aws/lambda/my-function"}]}
        ]
        mock_logs.get_paginator.return_value = mock_paginator

        analyzer.get_client = MagicMock(return_value=mock_logs)

        analyzer._check_metric_filters()

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM
        assert "No CloudTrail log groups" in analyzer.findings[0].title

    def test_missing_metric_filters(self):
        analyzer = _make_analyzer()
        mock_logs = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"logGroups": [{"logGroupName": "cloudtrail-logs"}]}
        ]
        mock_logs.get_paginator.return_value = mock_paginator
        mock_logs.describe_metric_filters.return_value = {"metricFilters": []}

        analyzer.get_client = MagicMock(return_value=mock_logs)

        analyzer._check_metric_filters()

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.LOW
        assert "Missing" in analyzer.findings[0].title

    def test_all_metric_filters_present(self):
        analyzer = _make_analyzer()
        mock_logs = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"logGroups": [{"logGroupName": "cloudtrail-logs"}]}
        ]
        mock_logs.get_paginator.return_value = mock_paginator

        # Return all 14 expected filter names
        all_filters = [
            "UnauthorizedAPICalls",
            "ConsoleSignInWithoutMFA",
            "RootAccountUsage",
            "IAMPolicyChanges",
            "CloudTrailConfigChanges",
            "ConsoleAuthFailures",
            "CMKDeletion",
            "S3BucketPolicyChanges",
            "ConfigChanges",
            "SecurityGroupChanges",
            "NACLChanges",
            "NetworkGatewayChanges",
            "RouteTableChanges",
            "VPCChanges",
        ]
        mock_logs.describe_metric_filters.return_value = {
            "metricFilters": [{"filterName": name} for name in all_filters]
        }

        analyzer.get_client = MagicMock(return_value=mock_logs)

        analyzer._check_metric_filters()

        assert len(analyzer.findings) == 0


class TestCloudTrailAnalyzerHandler:
    @patch("analyzers.cloudtrail_analyzer.run_analyzer")
    def test_handler_delegates(self, mock_run):
        mock_run.return_value = {"success": True}
        handler({"assessmentId": "test"}, None)
        mock_run.assert_called_once_with(CloudTrailAnalyzer, {"assessmentId": "test"})
