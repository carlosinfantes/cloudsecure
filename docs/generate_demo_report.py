#!/usr/bin/env python3
"""Generate a demo CloudSecure report with fictitious data and take screenshots."""

import os
import sys

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "lambdas", "report_generator", "templates")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "screenshots")

# --- Fictitious assessment data ---

ASSESSMENT = {
    "assessmentId": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
    "accountId": "123456789012",
    "startedAt": "2026-03-01T09:15:00Z",
    "riskScore": 47,
    "riskLevel": "MEDIUM",
    "executiveSummary": (
        "The AWS security assessment of account 123456789012 reveals a moderate risk posture "
        "with several areas requiring immediate attention. While foundational security controls "
        "are partially in place, significant gaps exist in IAM credential management, network "
        "segmentation, and encryption coverage.\n\n"
        "The most critical findings relate to an IAM user with full administrative access "
        "and active access keys that have not been rotated in over 180 days, combined with "
        "two security groups allowing unrestricted SSH access from the internet. These "
        "issues create a direct attack surface that could be exploited for initial access "
        "and lateral movement.\n\n"
        "Positively, S3 bucket-level public access blocks are enabled at the account level, "
        "CloudTrail is active with multi-region logging, and RDS instances are encrypted. "
        "However, 3 EBS volumes and 1 EFS filesystem remain unencrypted, and several S3 "
        "buckets lack versioning and access logging."
    ),
    "keyFindings": [
        "IAM user 'deploy-admin' has AdministratorAccess policy with access keys unused for 182 days — immediate credential rotation required",
        "2 security groups allow inbound SSH (port 22) from 0.0.0.0/0, exposing EC2 instances to brute-force attacks",
        "Root account was used 12 times in the last 90 days without MFA hardware token enforcement",
        "3 EBS volumes in eu-west-1 are not encrypted, violating the organization's encryption-at-rest policy",
        "CloudTrail log file validation is disabled, allowing potential tampering with audit logs",
    ],
    "patterns": [
        "Encryption gaps across multiple services: EBS (3 volumes), EFS (1 filesystem), and 2 S3 buckets without default encryption — suggests missing organization-wide encryption policy",
        "Overly permissive network rules: 4 security groups with 0.0.0.0/0 rules across SSH, RDP, and HTTPS — indicates lack of network segmentation standards",
        "Stale credentials: 5 IAM users with access keys older than 90 days, 2 users without MFA — points to missing credential lifecycle management",
        "Logging inconsistencies: CloudTrail active but log validation disabled; 6 S3 buckets without access logging — partial observability coverage",
    ],
    "remediationPriorities": [
        "IMMEDIATE: Rotate or deactivate access keys for 'deploy-admin' user and enforce MFA on all IAM users with console access",
        "IMMEDIATE: Restrict security groups sg-0a1b2c3d and sg-4e5f6a7b to specific CIDR ranges for SSH/RDP access",
        "HIGH: Enable EBS default encryption in all regions and encrypt existing unencrypted volumes via snapshot-copy workflow",
        "HIGH: Enable CloudTrail log file validation and configure CloudWatch metric filters for unauthorized API calls",
        "MEDIUM: Enable S3 access logging and versioning on all buckets; deploy S3 Lifecycle policies for cost optimization",
    ],
}

# --- Fictitious findings ---

FINDINGS = [
    # CRITICAL (2)
    {
        "severity": "CRITICAL",
        "title": "IAM user with AdministratorAccess and stale keys",
        "description": "IAM user 'deploy-admin' has AdministratorAccess policy attached with access keys last used 182 days ago. Long-lived admin credentials significantly increase the blast radius of a credential compromise.",
        "source": "iam-analyzer",
        "resourceType": "AWS::IAM::User",
        "resourceId": "deploy-admin",
        "region": "global",
    },
    {
        "severity": "CRITICAL",
        "title": "Security group allows unrestricted SSH from internet",
        "description": "Security group 'sg-0a1b2c3d' allows inbound SSH (TCP port 22) from 0.0.0.0/0. This exposes associated EC2 instances to brute-force and credential stuffing attacks from the entire internet.",
        "source": "network-analyzer",
        "resourceType": "AWS::EC2::SecurityGroup",
        "resourceId": "sg-0a1b2c3d (web-servers-ssh)",
        "region": "eu-west-1",
    },
    # HIGH (5)
    {
        "severity": "HIGH",
        "title": "Root account used without hardware MFA",
        "description": "The root account was used 12 times in the past 90 days. Root account usage should be minimized and protected with a hardware MFA device for maximum security.",
        "source": "iam-analyzer",
        "resourceType": "AWS::IAM::Root",
        "resourceId": "root",
        "region": "global",
    },
    {
        "severity": "HIGH",
        "title": "Security group allows unrestricted RDP from internet",
        "description": "Security group 'sg-4e5f6a7b' allows inbound RDP (TCP port 3389) from 0.0.0.0/0. Remote Desktop exposed to the internet is a common initial access vector for ransomware attacks.",
        "source": "network-analyzer",
        "resourceType": "AWS::EC2::SecurityGroup",
        "resourceId": "sg-4e5f6a7b (windows-mgmt)",
        "region": "eu-west-1",
    },
    {
        "severity": "HIGH",
        "title": "CloudTrail log file validation disabled",
        "description": "CloudTrail trail 'management-trail' does not have log file validation enabled. Without validation, log files could be modified or deleted without detection, undermining forensic investigations.",
        "source": "cloudtrail-analyzer",
        "resourceType": "AWS::CloudTrail::Trail",
        "resourceId": "management-trail",
        "region": "eu-west-1",
    },
    {
        "severity": "HIGH",
        "title": "EBS volume not encrypted",
        "description": "EBS volume 'vol-0ab12cd34ef56gh78' is not encrypted at rest. Unencrypted volumes expose data to unauthorized access if the underlying physical storage is compromised.",
        "source": "encryption-analyzer",
        "resourceType": "AWS::EC2::Volume",
        "resourceId": "vol-0ab12cd34ef56gh78",
        "region": "eu-west-1",
    },
    {
        "severity": "HIGH",
        "title": "IAM password policy does not meet CIS benchmark",
        "description": "The account password policy allows passwords shorter than 14 characters and does not require symbol characters, falling below CIS AWS Foundations Benchmark 1.4 requirements.",
        "source": "iam-analyzer",
        "resourceType": "AWS::IAM::AccountPasswordPolicy",
        "resourceId": "password-policy",
        "region": "global",
    },
    # MEDIUM (12)
    {
        "severity": "MEDIUM",
        "title": "S3 bucket without access logging",
        "description": "S3 bucket 'app-data-prod-eu' does not have server access logging enabled. Access logs are essential for security auditing and incident investigation.",
        "source": "s3-analyzer",
        "resourceType": "AWS::S3::Bucket",
        "resourceId": "app-data-prod-eu",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "S3 bucket without versioning",
        "description": "S3 bucket 'terraform-state-prod' does not have versioning enabled. Without versioning, accidental deletions or overwrites cannot be recovered.",
        "source": "s3-analyzer",
        "resourceType": "AWS::S3::Bucket",
        "resourceId": "terraform-state-prod",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "EFS filesystem not encrypted",
        "description": "EFS filesystem 'fs-0123456789abcdef0' is not encrypted at rest. EFS encryption should be enabled at creation time to protect stored data.",
        "source": "encryption-analyzer",
        "resourceType": "AWS::EFS::FileSystem",
        "resourceId": "fs-0123456789abcdef0",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "IAM user without MFA enabled",
        "description": "IAM user 'ci-pipeline' has console access but no MFA device configured. All users with console access should have MFA enabled.",
        "source": "iam-analyzer",
        "resourceType": "AWS::IAM::User",
        "resourceId": "ci-pipeline",
        "region": "global",
    },
    {
        "severity": "MEDIUM",
        "title": "IAM user without MFA enabled",
        "description": "IAM user 'data-analyst' has console access but no MFA device configured.",
        "source": "iam-analyzer",
        "resourceType": "AWS::IAM::User",
        "resourceId": "data-analyst",
        "region": "global",
    },
    {
        "severity": "MEDIUM",
        "title": "Security group allows unrestricted HTTPS",
        "description": "Security group 'sg-7h8i9j0k' allows inbound HTTPS (TCP port 443) from 0.0.0.0/0. While common for web servers, ensure this is intentional and behind a load balancer.",
        "source": "network-analyzer",
        "resourceType": "AWS::EC2::SecurityGroup",
        "resourceId": "sg-7h8i9j0k (api-public)",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "VPC Flow Logs not enabled",
        "description": "VPC 'vpc-0aabb1122cc334455' does not have Flow Logs enabled. Flow Logs provide visibility into network traffic for security monitoring and troubleshooting.",
        "source": "network-analyzer",
        "resourceType": "AWS::EC2::VPC",
        "resourceId": "vpc-0aabb1122cc334455",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "EBS volume not encrypted",
        "description": "EBS volume 'vol-1bc23de45fg67hi89' is not encrypted at rest.",
        "source": "encryption-analyzer",
        "resourceType": "AWS::EC2::Volume",
        "resourceId": "vol-1bc23de45fg67hi89",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "EBS volume not encrypted",
        "description": "EBS volume 'vol-2cd34ef56gh78ij90' is not encrypted at rest.",
        "source": "encryption-analyzer",
        "resourceType": "AWS::EC2::Volume",
        "resourceId": "vol-2cd34ef56gh78ij90",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "S3 bucket without access logging",
        "description": "S3 bucket 'cloudtrail-logs-archive' does not have access logging enabled.",
        "source": "s3-analyzer",
        "resourceType": "AWS::S3::Bucket",
        "resourceId": "cloudtrail-logs-archive",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "CloudWatch metric filter missing for root usage",
        "description": "No CloudWatch metric filter detected for root account usage events. CIS 1.4 recommends monitoring root activity via metric filters and alarms.",
        "source": "cloudtrail-analyzer",
        "resourceType": "AWS::Logs::MetricFilter",
        "resourceId": "N/A",
        "region": "eu-west-1",
    },
    {
        "severity": "MEDIUM",
        "title": "Prowler: Ensure IAM policies do not allow full * administrative privileges",
        "description": "CIS 1.16 - IAM policy 'LegacyAdminPolicy' allows Action:* on Resource:*. Policies granting full administrative privileges should be reviewed and scoped down.",
        "source": "prowler-scanner",
        "resourceType": "AWS::IAM::Policy",
        "resourceId": "LegacyAdminPolicy",
        "region": "global",
    },
    # LOW (20)
    *[
        {
            "severity": "LOW",
            "title": title,
            "description": desc,
            "source": source,
            "resourceType": rtype,
            "resourceId": rid,
            "region": region,
        }
        for title, desc, source, rtype, rid, region in [
            ("S3 bucket without default encryption configuration", "S3 bucket 'legacy-uploads' does not have default encryption configured. While S3 now encrypts by default, explicit configuration ensures compliance visibility.", "s3-analyzer", "AWS::S3::Bucket", "legacy-uploads", "eu-west-1"),
            ("S3 bucket without default encryption configuration", "S3 bucket 'temp-processing' does not have default encryption configured.", "s3-analyzer", "AWS::S3::Bucket", "temp-processing", "eu-west-1"),
            ("IAM access key older than 90 days", "Access key for user 'app-service' is 147 days old. Regular key rotation limits the window of exposure for compromised credentials.", "iam-analyzer", "AWS::IAM::AccessKey", "app-service/AKIA...", "global"),
            ("IAM access key older than 90 days", "Access key for user 'monitoring-agent' is 203 days old.", "iam-analyzer", "AWS::IAM::AccessKey", "monitoring-agent/AKIA...", "global"),
            ("IAM access key older than 90 days", "Access key for user 'backup-runner' is 112 days old.", "iam-analyzer", "AWS::IAM::AccessKey", "backup-runner/AKIA...", "global"),
            ("Default VPC in use", "The default VPC in eu-west-1 is in use with 2 running instances. Default VPCs have less restrictive configurations than custom VPCs.", "network-analyzer", "AWS::EC2::VPC", "vpc-default", "eu-west-1"),
            ("Security group with unused rules", "Security group 'sg-old-rules-123' has 3 inbound rules referencing IP ranges no longer in use.", "network-analyzer", "AWS::EC2::SecurityGroup", "sg-old-rules-123", "eu-west-1"),
            ("S3 bucket without lifecycle policy", "S3 bucket 'app-logs-raw' does not have a lifecycle policy. Old objects accumulate costs without automatic transitions or expiration.", "s3-analyzer", "AWS::S3::Bucket", "app-logs-raw", "eu-west-1"),
            ("S3 bucket without lifecycle policy", "S3 bucket 'etl-staging' does not have a lifecycle policy.", "s3-analyzer", "AWS::S3::Bucket", "etl-staging", "eu-west-1"),
            ("CloudTrail not using KMS encryption", "CloudTrail trail 'management-trail' uses default SSE-S3 encryption instead of KMS. KMS provides additional access controls and audit logging for trail data.", "cloudtrail-analyzer", "AWS::CloudTrail::Trail", "management-trail", "eu-west-1"),
            ("EBS default encryption not enabled", "EBS default encryption is not enabled in eu-west-1. Enabling it ensures all new volumes are automatically encrypted.", "encryption-analyzer", "AWS::EC2::EBSDefaultEncryption", "eu-west-1", "eu-west-1"),
            ("Prowler: Ensure CloudTrail trails are integrated with CloudWatch Logs", "CIS 3.4 - Trail 'management-trail' is not integrated with CloudWatch Logs for real-time monitoring.", "prowler-scanner", "AWS::CloudTrail::Trail", "management-trail", "eu-west-1"),
            ("Prowler: Ensure a log metric filter for unauthorized API calls", "CIS 3.1 - No metric filter exists for unauthorized API call attempts.", "prowler-scanner", "AWS::Logs::MetricFilter", "N/A", "eu-west-1"),
            ("Prowler: Ensure a log metric filter for IAM policy changes", "CIS 3.4 - No metric filter exists for IAM policy change events.", "prowler-scanner", "AWS::Logs::MetricFilter", "N/A", "eu-west-1"),
            ("Prowler: Ensure a log metric filter for security group changes", "CIS 3.10 - No metric filter exists for security group change events.", "prowler-scanner", "AWS::Logs::MetricFilter", "N/A", "eu-west-1"),
            ("GuardDuty finding: Unusual API activity", "GuardDuty detected unusual DescribeInstances API calls from an IP not previously seen in account activity.", "native-service-puller", "AWS::GuardDuty::Finding", "guardduty-finding-001", "eu-west-1"),
            ("S3 bucket without access logging", "S3 bucket 'config-snapshots' does not have access logging enabled.", "s3-analyzer", "AWS::S3::Bucket", "config-snapshots", "eu-west-1"),
            ("S3 bucket without versioning", "S3 bucket 'etl-staging' does not have versioning enabled.", "s3-analyzer", "AWS::S3::Bucket", "etl-staging", "eu-west-1"),
            ("IAM user with inline policy", "IAM user 'legacy-deploy' has an inline policy instead of a managed policy. Inline policies are harder to audit and manage at scale.", "iam-analyzer", "AWS::IAM::User", "legacy-deploy", "global"),
            ("Prowler: Ensure rotation for customer-created CMKs is enabled", "CIS 2.8 - KMS key 'alias/app-encryption' does not have automatic rotation enabled.", "prowler-scanner", "AWS::KMS::Key", "alias/app-encryption", "eu-west-1"),
        ]
    ],
    # INFO (6)
    {
        "severity": "INFO",
        "title": "SecurityHub not enabled",
        "description": "AWS Security Hub is not enabled in this account. Security Hub provides a centralized view of security findings across AWS services.",
        "source": "native-service-puller",
        "resourceType": "AWS::SecurityHub::Hub",
        "resourceId": "N/A",
        "region": "eu-west-1",
    },
    {
        "severity": "INFO",
        "title": "AWS Config not enabled",
        "description": "AWS Config is not enabled in this account. Config provides resource inventory and configuration change tracking.",
        "source": "native-service-puller",
        "resourceType": "AWS::Config::ConfigurationRecorder",
        "resourceId": "N/A",
        "region": "eu-west-1",
    },
    {
        "severity": "INFO",
        "title": "Inspector not enabled",
        "description": "Amazon Inspector v2 is not enabled. Inspector provides automated vulnerability scanning for EC2, Lambda, and ECR.",
        "source": "native-service-puller",
        "resourceType": "AWS::Inspector2::Inspector",
        "resourceId": "N/A",
        "region": "eu-west-1",
    },
    {
        "severity": "INFO",
        "title": "Macie not enabled",
        "description": "Amazon Macie is not enabled. Macie uses machine learning to discover and protect sensitive data in S3.",
        "source": "native-service-puller",
        "resourceType": "AWS::Macie::Session",
        "resourceId": "N/A",
        "region": "eu-west-1",
    },
    {
        "severity": "INFO",
        "title": "Account has 14 IAM users",
        "description": "The account has 14 IAM users. Consider using IAM Identity Center (SSO) for centralized user management and temporary credentials.",
        "source": "iam-analyzer",
        "resourceType": "AWS::IAM::AccountSummary",
        "resourceId": "N/A",
        "region": "global",
    },
    {
        "severity": "INFO",
        "title": "3 VPCs discovered across 1 region",
        "description": "The account has 3 VPCs in eu-west-1: vpc-prod, vpc-staging, and the default VPC.",
        "source": "network-analyzer",
        "resourceType": "AWS::EC2::VPC",
        "resourceId": "3 VPCs",
        "region": "eu-west-1",
    },
]

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#17a2b8",
    "INFO": "#6c757d",
}


def render_report():
    """Render the Jinja2 template with fictitious data."""
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")

    # Group findings by severity
    findings_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in FINDINGS:
        findings_by_severity[f["severity"]].append(f)

    # Group findings by category
    findings_by_category = {}
    for f in FINDINGS:
        source = f.get("source", "unknown")
        category = source.replace("-analyzer", "").replace("_", " ").replace("-", " ").title()
        findings_by_category.setdefault(category, []).append(f)

    html = template.render(
        assessment=ASSESSMENT,
        findings=FINDINGS,
        findings_by_severity=findings_by_severity,
        findings_by_category=findings_by_category,
        generated_at="2026-03-01 10:32:15 UTC",
        severity_colors=SEVERITY_COLORS,
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    html_path = os.path.join(OUTPUT_DIR, "demo-report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"HTML report written to {html_path}")
    return html_path


def take_screenshots(html_path: str):
    """Take screenshots of the report using Playwright."""
    from playwright.sync_api import sync_playwright

    file_url = f"file://{html_path}"

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1400, "height": 8000})
        page.goto(file_url)
        page.wait_for_load_state("networkidle")

        # 1. Full page screenshot
        page.screenshot(
            path=os.path.join(OUTPUT_DIR, "report-full.png"),
            full_page=True,
        )
        print("Captured: report-full.png")

        # 2. Header + risk score
        header = page.locator("header")
        risk = page.locator(".risk-score")
        header_box = header.bounding_box()
        risk_box = risk.bounding_box()
        if header_box and risk_box:
            page.screenshot(
                path=os.path.join(OUTPUT_DIR, "report-header.png"),
                clip={
                    "x": 0,
                    "y": 0,
                    "width": 1400,
                    "height": risk_box["y"] + risk_box["height"] + 20,
                },
            )
            print("Captured: report-header.png")

        # 3. Findings summary (severity cards)
        sections = page.locator("section")
        first_section = sections.nth(0)
        box = first_section.bounding_box()
        if box:
            page.screenshot(
                path=os.path.join(OUTPUT_DIR, "report-summary.png"),
                clip={
                    "x": 0,
                    "y": box["y"] - 10,
                    "width": 1400,
                    "height": box["height"] + 20,
                },
            )
            print("Captured: report-summary.png")

        # 4. Executive summary
        exec_section = page.locator("section:has(.executive-summary)")
        box = exec_section.bounding_box()
        if box:
            page.screenshot(
                path=os.path.join(OUTPUT_DIR, "report-executive.png"),
                clip={
                    "x": 0,
                    "y": box["y"] - 10,
                    "width": 1400,
                    "height": box["height"] + 20,
                },
            )
            print("Captured: report-executive.png")

        # 5. First findings table (detailed findings)
        findings_section = page.locator(".category-section").first
        box = findings_section.bounding_box()
        if box:
            page.screenshot(
                path=os.path.join(OUTPUT_DIR, "report-findings.png"),
                clip={
                    "x": 0,
                    "y": box["y"] - 40,
                    "width": 1400,
                    "height": min(box["height"] + 60, 900),
                },
            )
            print("Captured: report-findings.png")

        browser.close()


if __name__ == "__main__":
    html_path = render_report()
    if "--no-screenshots" not in sys.argv:
        take_screenshots(html_path)
    print(f"\nAll done! Files in {OUTPUT_DIR}/")
