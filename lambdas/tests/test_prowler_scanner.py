"""Tests for the Prowler scanner Lambda: check list, version pin and scope."""

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from prowler_scanner import handler as scanner

DOCKERFILE = Path(__file__).resolve().parents[1] / "prowler_scanner" / "Dockerfile"

EVENT = {
    "assessmentId": "11111111-1111-1111-1111-111111111111",
    "accountId": "123456789012",
    "roleArn": "arn:aws:iam::123456789012:role/CloudSecureAssessmentRole",
    "externalId": "external-id-1234",
    "regions": ["eu-west-1"],
}

# IDs that never existed in Prowler. They shipped in main and would have made
# every scan exit 1, because Prowler rejects unknown check IDs since 5.14.
INVALID_CHECK_IDS = {
    "eks_cluster_logging_enabled",
    "eks_cluster_endpoint_public_access_disabled",
    "eks_cluster_secrets_encryption_enabled",
    "eks_cluster_uses_latest_kubernetes_version",
    "eks_cluster_control_plane_audit_logging_enabled",
}


class TestCheckList:
    def test_no_duplicate_checks(self):
        assert len(scanner.ALL_CHECKS) == len(set(scanner.ALL_CHECKS))

    def test_no_invalid_check_ids(self):
        assert not INVALID_CHECK_IDS.intersection(scanner.ALL_CHECKS)

    def test_every_scope_maps_to_known_checks(self):
        for scope, checks in scanner.SCOPE_CHECKS.items():
            assert checks, f"scope {scope} resolves to no checks"
            unknown = set(checks) - set(scanner.ALL_CHECKS)
            assert not unknown, f"scope {scope} references unknown checks: {unknown}"

    def test_version_pin_matches_dockerfile(self):
        """An unpinned or drifting image silently changes check IDs."""
        pinned = re.search(r'prowler==([0-9.]+)"', DOCKERFILE.read_text())
        assert pinned, "Dockerfile must pin an exact Prowler version"
        assert pinned.group(1) == scanner.PROWLER_VERSION


class TestScopeResolution:
    @pytest.fixture
    def stubbed_scan(self):
        """Stub everything that would touch AWS or run the Prowler binary."""
        with (
            patch.object(scanner, "update_assessment_progress"),
            patch.object(
                scanner,
                "assume_role",
                return_value={
                    "AccessKeyId": "k",
                    "SecretAccessKey": "s",
                    "SessionToken": "t",
                },
            ),
            patch.object(scanner, "parse_prowler_output", return_value=[]),
            patch.object(
                scanner, "run_prowler", return_value={"success": True, "version": "5.42.0"}
            ) as run_prowler,
        ):
            yield run_prowler

    def test_scope_all_runs_every_check(self, stubbed_scan):
        scanner.handler({**EVENT, "scope": ["all"]}, None)

        assert stubbed_scan.call_args.kwargs["checks"] == scanner.ALL_CHECKS

    def test_scope_iam_runs_only_iam_checks(self, stubbed_scan):
        scanner.handler({**EVENT, "scope": ["iam"]}, None)

        checks = stubbed_scan.call_args.kwargs["checks"]
        assert checks
        assert all(c.startswith("iam_") for c in checks)

    def test_scopes_are_combined_without_duplicates(self, stubbed_scan):
        scanner.handler({**EVENT, "scope": ["network", "vpc"]}, None)

        checks = stubbed_scan.call_args.kwargs["checks"]
        assert len(checks) == len(set(checks))
        assert "vpc_flow_logs_enabled" in checks

    def test_missing_scope_defaults_to_all(self, stubbed_scan):
        scanner.handler(EVENT, None)

        assert stubbed_scan.call_args.kwargs["checks"] == scanner.ALL_CHECKS

    def test_scope_without_prowler_checks_skips_the_scan(self, stubbed_scan):
        result = scanner.handler({**EVENT, "scope": ["cloudtrail-only-typo"]}, None)

        assert result["skipped"] is True
        assert result["findingsCount"] == 0
        stubbed_scan.assert_not_called()
