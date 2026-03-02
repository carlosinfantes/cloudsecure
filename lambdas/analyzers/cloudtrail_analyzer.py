"""CloudTrail Analyzer - Detects logging and audit issues.

Checks for:
1. CloudTrail not enabled
2. CloudTrail not logging to S3 with validation
3. CloudTrail logs not encrypted
4. Root account usage
5. Management events not logged
6. CloudTrail not multi-region
"""

import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.base import BaseAnalyzer, run_analyzer
from shared.models import (
    ComplianceFramework,
    ComplianceMapping,
    Finding,
    FindingSeverity,
    Remediation,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class CloudTrailAnalyzer(BaseAnalyzer):
    """Analyzer for CloudTrail and logging security issues."""

    @property
    def name(self) -> str:
        return "cloudtrail-analyzer"

    def analyze(self) -> list[Finding]:
        """Run CloudTrail security analysis."""
        self.log_info("Starting CloudTrail analysis")

        # CloudTrail is configured regionally but can be multi-region
        cloudtrail = self.get_client("cloudtrail", "us-east-1")

        # Check trail configuration
        self._check_trails(cloudtrail)

        # Check for recent root account usage
        self._check_root_usage(cloudtrail)

        # Check CloudWatch alarms for security events
        self._check_metric_filters()

        self.log_info(f"CloudTrail analysis complete. Found {len(self.findings)} findings")
        return self.findings

    def _check_trails(self, cloudtrail: Any) -> None:
        """Check CloudTrail trail configuration."""
        self.log_info("Checking CloudTrail trails")

        try:
            trails = cloudtrail.describe_trails()["trailList"]

            if not trails:
                self.create_finding(
                    severity=FindingSeverity.CRITICAL,
                    title="No CloudTrail trails are configured",
                    description=(
                        "No CloudTrail trails are configured in this account. "
                        "CloudTrail is essential for auditing API activity and security monitoring."
                    ),
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id="no-trail",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="3.1",
                            description="Ensure CloudTrail is enabled in all regions",
                        ),
                    ],
                    remediation=Remediation(
                        description="Create a CloudTrail trail",
                        steps=[
                            "Navigate to CloudTrail console",
                            "Click 'Create trail'",
                            "Enable multi-region trail",
                            "Enable log file validation",
                            "Configure S3 bucket and optional KMS encryption",
                        ],
                        automatable=True,
                        effort="MEDIUM",
                    ),
                )
                return

            has_multi_region = False
            has_management_events = False

            for trail in trails:
                trail_name = trail["Name"]
                trail_arn = trail.get("TrailARN", "")

                # Check if multi-region
                if trail.get("IsMultiRegionTrail", False):
                    has_multi_region = True

                # Check log file validation
                if trail.get("LogFileValidationEnabled", False):
                    pass  # Log validation is enabled
                else:
                    self.create_finding(
                        severity=FindingSeverity.MEDIUM,
                        title=f"CloudTrail '{trail_name}' does not have log file validation enabled",
                        description=(
                            f"The CloudTrail trail '{trail_name}' does not have log file validation "
                            "enabled. This makes it harder to detect if logs have been tampered with."
                        ),
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id=trail_name,
                        resource_arn=trail_arn,
                        compliance_mappings=[
                            ComplianceMapping(
                                framework=ComplianceFramework.CIS_AWS_1_4,
                                control="3.2",
                                description="Ensure CloudTrail log file validation is enabled",
                            ),
                        ],
                        remediation=Remediation(
                            description="Enable log file validation",
                            steps=[
                                f"Navigate to CloudTrail > Trails > {trail_name}",
                                "Click 'Edit'",
                                "Enable 'Log file validation'",
                            ],
                            automatable=True,
                            effort="LOW",
                        ),
                    )

                # Check encryption (API returns 'KmsKeyId', not 'KMSKeyId')
                if trail.get("KmsKeyId"):
                    pass  # Encryption is enabled
                else:
                    self.create_finding(
                        severity=FindingSeverity.MEDIUM,
                        title=f"CloudTrail '{trail_name}' logs are not encrypted with KMS",
                        description=(
                            f"The CloudTrail trail '{trail_name}' is not configured to encrypt "
                            "logs with a KMS key. While S3 may have default encryption, explicit "
                            "KMS encryption provides better access control."
                        ),
                        resource_type="AWS::CloudTrail::Trail",
                        resource_id=trail_name,
                        resource_arn=trail_arn,
                        compliance_mappings=[
                            ComplianceMapping(
                                framework=ComplianceFramework.CIS_AWS_1_4,
                                control="3.7",
                                description="Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
                            ),
                        ],
                        remediation=Remediation(
                            description="Enable KMS encryption for CloudTrail logs",
                            steps=[
                                f"Navigate to CloudTrail > Trails > {trail_name}",
                                "Click 'Edit'",
                                "Enable SSE-KMS encryption",
                                "Select or create a KMS key",
                            ],
                            automatable=True,
                            effort="LOW",
                        ),
                    )

                # Check event selectors for management events
                # Use the trail ARN for organization trails (trail name alone
                # won't work for trails owned by a different account).
                trail_identifier = trail_arn or trail_name
                try:
                    selectors = cloudtrail.get_event_selectors(TrailName=trail_identifier)

                    # Check basic event selectors
                    for selector in selectors.get("EventSelectors", []):
                        if selector.get("IncludeManagementEvents", False):
                            has_management_events = True

                    # Check advanced event selectors
                    for _selector in selectors.get("AdvancedEventSelectors", []):
                        # Advanced selectors include management events by default
                        has_management_events = True

                except ClientError as e:
                    self.log_warning(f"Could not get event selectors for {trail_identifier}: {e}")

                # Check if trail is logging (use ARN for org trails)
                try:
                    status = cloudtrail.get_trail_status(Name=trail_identifier)
                    if not status.get("IsLogging", False):
                        self.create_finding(
                            severity=FindingSeverity.CRITICAL,
                            title=f"CloudTrail '{trail_name}' is not currently logging",
                            description=(
                                f"The CloudTrail trail '{trail_name}' exists but is not actively "
                                "logging. API activity is not being recorded."
                            ),
                            resource_type="AWS::CloudTrail::Trail",
                            resource_id=trail_name,
                            resource_arn=trail_arn,
                            remediation=Remediation(
                                description="Start CloudTrail logging",
                                steps=[
                                    f"Navigate to CloudTrail > Trails > {trail_name}",
                                    "Click 'Start logging'",
                                ],
                                automatable=True,
                                effort="LOW",
                            ),
                        )
                except ClientError as e:
                    self.log_warning(f"Could not get trail status for {trail_name}: {e}")

            # Check for multi-region trail
            if not has_multi_region:
                self.create_finding(
                    severity=FindingSeverity.HIGH,
                    title="No multi-region CloudTrail trail is configured",
                    description=(
                        "No CloudTrail trail is configured as multi-region. API activity in "
                        "some regions may not be logged."
                    ),
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id="multi-region-trail",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="3.1",
                            description="Ensure CloudTrail is enabled in all regions",
                        ),
                    ],
                    remediation=Remediation(
                        description="Configure a multi-region trail",
                        steps=[
                            "Edit an existing trail or create a new one",
                            "Enable 'Apply trail to all regions'",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

            # Check for management events
            if not has_management_events:
                self.create_finding(
                    severity=FindingSeverity.HIGH,
                    title="No CloudTrail trail is logging management events",
                    description=(
                        "No CloudTrail trail is configured to log management events. "
                        "Control plane operations (API calls) are not being recorded."
                    ),
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id="management-events",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="3.1",
                            description="Ensure management console sign-in without MFA is monitored",
                        ),
                    ],
                    remediation=Remediation(
                        description="Enable management events logging",
                        steps=[
                            "Edit a CloudTrail trail",
                            "Configure event selectors to include management events",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

        except ClientError as e:
            self.log_error(f"Error checking CloudTrail trails: {e}")

    def _check_root_usage(self, cloudtrail: Any) -> None:
        """Check for recent root account usage.

        Filters out AWS Organizations 'assumedRoot' events which are automated
        management actions from the organization management account, not actual
        human root logins.
        """
        self.log_info("Checking for root account usage")

        try:
            # Look back 90 days for root usage
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(days=90)

            # Look up events by root user
            events = cloudtrail.lookup_events(
                LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "root"}],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50,
            )

            # Filter out assumedRoot events (automated org management actions)
            import json as _json

            real_root_events = []
            assumed_root_count = 0
            for event in events.get("Events", []):
                try:
                    detail = _json.loads(event.get("CloudTrailEvent", "{}"))
                    session_ctx = detail.get("userIdentity", {}).get("sessionContext", {})
                    if session_ctx.get("assumedRoot") == "true":
                        assumed_root_count += 1
                        continue
                except (ValueError, TypeError):
                    pass
                real_root_events.append(event)

            if assumed_root_count > 0:
                self.log_info(
                    f"Filtered out {assumed_root_count} assumedRoot events "
                    "(automated org management actions)"
                )

            if real_root_events:
                # Group by event type
                event_types: dict[str, int] = {}
                for event in real_root_events:
                    event_name = event.get("EventName", "Unknown")
                    event_types[event_name] = event_types.get(event_name, 0) + 1

                self.create_finding(
                    severity=FindingSeverity.HIGH,
                    title=f"Root account has been used {len(real_root_events)} times in the last 90 days",
                    description=(
                        f"The root account has been used {len(real_root_events)} times in the last 90 days. "
                        f"Event types: {', '.join(f'{k}({v})' for k, v in event_types.items())}. "
                        "Root account usage should be minimized and closely monitored."
                    ),
                    resource_type="AWS::IAM::Root",
                    resource_id="root-usage",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="1.7",
                            description="Eliminate use of the root account for administrative tasks",
                        ),
                    ],
                    remediation=Remediation(
                        description="Minimize root account usage",
                        steps=[
                            "Create IAM users or roles for day-to-day tasks",
                            "Use IAM Identity Center for centralized access",
                            "Reserve root account for tasks that require it",
                            "Enable alerts for root account usage",
                        ],
                        automatable=False,
                        effort="MEDIUM",
                    ),
                    metadata={
                        "eventCount": len(real_root_events),
                        "eventTypes": event_types,
                        "lookbackDays": 90,
                    },
                )

        except ClientError as e:
            self.log_error(f"Error checking root usage: {e}")

    def _check_metric_filters(self) -> None:
        """Check for CloudWatch metric filters on security events."""
        self.log_info("Checking CloudWatch metric filters")

        # List of recommended metric filters per CIS
        recommended_filters = [
            ("UnauthorizedAPICalls", "3.1", "unauthorized API calls"),
            ("ConsoleSignInWithoutMFA", "3.2", "console sign-in without MFA"),
            ("RootAccountUsage", "3.3", "root account usage"),
            ("IAMPolicyChanges", "3.4", "IAM policy changes"),
            ("CloudTrailConfigChanges", "3.5", "CloudTrail configuration changes"),
            ("ConsoleAuthFailures", "3.6", "console authentication failures"),
            ("CMKDeletion", "3.7", "CMK deletion or disable"),
            ("S3BucketPolicyChanges", "3.8", "S3 bucket policy changes"),
            ("ConfigChanges", "3.9", "AWS Config changes"),
            ("SecurityGroupChanges", "3.10", "security group changes"),
            ("NACLChanges", "3.11", "NACL changes"),
            ("NetworkGatewayChanges", "3.12", "network gateway changes"),
            ("RouteTableChanges", "3.13", "route table changes"),
            ("VPCChanges", "3.14", "VPC changes"),
        ]

        try:
            logs = self.get_client("logs", "us-east-1")

            # Get all log groups that might have CloudTrail logs
            paginator = logs.get_paginator("describe_log_groups")
            cloudtrail_log_groups = []

            for page in paginator.paginate():
                for lg in page["logGroups"]:
                    name = lg["logGroupName"]
                    if "cloudtrail" in name.lower() or "trail" in name.lower():
                        cloudtrail_log_groups.append(name)

            if not cloudtrail_log_groups:
                self.create_finding(
                    severity=FindingSeverity.MEDIUM,
                    title="No CloudTrail log groups found in CloudWatch Logs",
                    description=(
                        "No CloudWatch Logs log groups for CloudTrail were found. "
                        "CloudTrail should be configured to send logs to CloudWatch for "
                        "real-time monitoring and alerting."
                    ),
                    resource_type="AWS::Logs::LogGroup",
                    resource_id="cloudtrail-logs",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="3.4",
                            description="Ensure CloudTrail trails are integrated with CloudWatch Logs",
                        ),
                    ],
                    remediation=Remediation(
                        description="Configure CloudTrail to send logs to CloudWatch",
                        steps=[
                            "Navigate to CloudTrail > Trails",
                            "Edit your trail",
                            "Enable CloudWatch Logs",
                            "Create or select a log group",
                            "Configure an IAM role for CloudTrail",
                        ],
                        automatable=True,
                        effort="MEDIUM",
                    ),
                )
                return

            # Check for metric filters on CloudTrail log groups
            existing_filters = set()

            for log_group in cloudtrail_log_groups:
                try:
                    filters = logs.describe_metric_filters(logGroupName=log_group)
                    for f in filters.get("metricFilters", []):
                        existing_filters.add(f["filterName"].lower())
                except ClientError:
                    pass

            # Check which recommended filters are missing
            missing_filters = []
            for filter_name, control, description in recommended_filters:
                # Check if any existing filter name contains the key terms
                found = any(filter_name.lower() in existing for existing in existing_filters)
                if not found:
                    missing_filters.append((filter_name, control, description))

            if missing_filters:
                self.create_finding(
                    severity=FindingSeverity.LOW,
                    title=f"Missing {len(missing_filters)} recommended CloudWatch metric filters",
                    description=(
                        f"The following recommended metric filters are not configured: "
                        f"{', '.join(f[2] for f in missing_filters[:5])}. "
                        "These filters help detect security-relevant events in real-time."
                    ),
                    resource_type="AWS::Logs::MetricFilter",
                    resource_id="metric-filters",
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control=missing_filters[0][1],
                            description=f"Ensure a metric filter for {missing_filters[0][2]} exists",
                        ),
                    ],
                    remediation=Remediation(
                        description="Create recommended metric filters",
                        steps=[
                            "Navigate to CloudWatch > Log groups",
                            "Select your CloudTrail log group",
                            "Create metric filters for security events",
                            "Create CloudWatch alarms for each metric",
                        ],
                        automatable=True,
                        effort="MEDIUM",
                    ),
                    metadata={
                        "missingFilters": [f[0] for f in missing_filters],
                        "existingFilters": list(existing_filters),
                    },
                )

        except ClientError as e:
            self.log_error(f"Error checking metric filters: {e}")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for CloudTrail analysis."""
    return run_analyzer(CloudTrailAnalyzer, event)
