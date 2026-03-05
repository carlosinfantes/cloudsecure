# CloudSecure Assessment Platform

An agentless, portable AWS security assessment platform that provides comprehensive security posture analysis regardless of what native AWS security services the customer has enabled.

## Why CloudSecure?

Traditional security tools like Prowler, ScoutSuite, or Steampipe run from a CLI on an engineer's laptop. That means:

- The auditor needs **long-lived credentials** (access keys) to the customer's account
- Credentials travel over the wire, get stored locally, and risk exposure
- There is no audit trail of *who* ran *what* and *when*
- Scaling to multiple accounts requires manual effort

**CloudSecure is different.** It runs **100% serverless inside AWS** — no CLI, no laptops, no credentials to share:

- **Delegated access via IAM roles**: Customers grant a read-only role to the CloudSecure account using `STS AssumeRole` with `ExternalId`. No credentials are ever exchanged — only trust is delegated.
- **Fully serverless**: Lambda, Step Functions, DynamoDB, S3 — nothing to install, patch, or maintain. The platform lives natively in AWS.
- **Auditable by design**: Every assessment is tracked in DynamoDB with a full execution trail through Step Functions. Customers can see exactly what was accessed and when.
- **Safe for customers**: Granting a cross-account read-only role is reversible, auditable (CloudTrail), and follows AWS best practices. Handing over access keys is none of those things.

## Overview

CloudSecure combines open-source security tools (Prowler), custom analysis modules, and AI-powered synthesis (AWS Bedrock Claude) to deliver actionable security insights for AWS environments.

### Key Features

- **100% Serverless**: Runs natively in AWS — no CLI, no infrastructure to manage
- **No Credentials Shared**: Cross-account access via IAM role delegation, not access keys
- **Agentless**: No software deployment required in customer accounts
- **AI-Powered**: Bedrock Claude synthesizes findings into actionable intelligence
- **Compliance-Ready**: Maps to CIS AWS 1.4, NIST 800-53, ISO 27001, GDPR, SOC2
- **Portable**: Can assess any AWS account with read permissions
- **Gap Detection**: Missing security services are findings, not blockers

## Report Demo

CloudSecure generates professional HTML reports with AI-powered executive summaries, risk scoring, and detailed findings across all security domains.

### Assessment Header & Risk Score
![Report Header](docs/screenshots/report-header.png)

### Findings Summary
![Findings Summary](docs/screenshots/report-summary.png)

### AI-Powered Executive Summary
![Executive Summary](docs/screenshots/report-executive.png)

### Detailed Findings by Category
![Detailed Findings](docs/screenshots/report-findings.png)

> Screenshots generated with fictitious data. See `docs/generate_demo_report.py` to regenerate.

## Project Information

| Field | Value |
|-------|-------|
| **Development** | SDD (Specification-Driven Development) |
| **Version** | 1.0.0 (Production Ready) |
| **License** | Apache-2.0 |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  CloudSecure Platform                        │
│  ┌─────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │   API   │──│ Step Functions│──│    Lambda Functions     │ │
│  │ Gateway │  │ Orchestrator  │  │ (Analyzers + Prowler)   │ │
│  └─────────┘  └──────────────┘  └─────────────────────────┘ │
│       │              │                      │                │
│  ┌─────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │DynamoDB │  │   Bedrock    │  │      S3 Reports         │ │
│  └─────────┘  │   Claude     │  └─────────────────────────┘ │
│               └──────────────┘                               │
└─────────────────────────────────────────────────────────────┘
                          │
                    STS AssumeRole
                          ▼
              ┌─────────────────────┐
              │  Customer Account   │
              │ (Read-Only Access)  │
              └─────────────────────┘
```

## Technology Stack

| Component | Technology |
|-----------|------------|
| Infrastructure | CDK (TypeScript) |
| Lambda Runtime | Python 3.12 |
| Orchestration | AWS Step Functions |
| API | API Gateway REST |
| Database | DynamoDB |
| Storage | S3 + KMS |
| AI | AWS Bedrock Claude 3.5 |
| Security Scanner | Prowler 5.x (Lambda Container) |
| Reports | HTML, JSON, CSV (Jinja2 templates) |
| CLI | Python (click, rich, boto3) — `pip install cloudsecure` |

### Active Analyzers

| Analyzer | Description | Status |
|----------|-------------|--------|
| IAM Analyzer | Users, roles, policies, MFA, credentials | Active |
| Network Analyzer | Security groups, VPCs, Flow Logs | Active |
| S3 Analyzer | Public buckets, encryption, logging | Active |
| Encryption Analyzer | EBS, RDS, EFS encryption | Active |
| CloudTrail Analyzer | Trail config, root usage, metric filters | Active |
| Native Service Puller | SecurityHub, GuardDuty, Config findings | Active |
| Prowler Scanner | CIS AWS benchmarks (17 critical checks) | Active |

## Branch Strategy

| Branch | Environment | AWS Account | Purpose |
|--------|-------------|-------------|---------|
| `dev` | Development | Local/Dev | Feature development, local testing |
| `test` | Testing | Test Account | Integration tests, QA validation |
| `main` | Production | Prod Account | Production deployments |

## Getting Started

### Prerequisites

- AWS CLI configured with an IAM profile
- Node.js 18+ and Python 3.12+
- Docker or Podman (optional — required for Prowler CIS scanner)

### Install the CLI

```bash
pip install cloudsecure
# or
pipx install cloudsecure
```

Or use the installer script:

```bash
curl -fsSL https://raw.githubusercontent.com/carlosinfantes/cloudsecure/main/install.sh | bash
```

### Deploy the Infrastructure

Interactive guided deployment:

```bash
git clone https://github.com/carlosinfantes/cloudsecure.git && cd cloudsecure
./deploy.sh
```

Or manually:

```bash
cp .env.example .env    # Edit with your AWS profile, region, etc.
make install && make deploy

# Deploy without Docker/Podman (skips Prowler)
SKIP_PROWLER=true make deploy
```

### Run an Assessment

```bash
# Start assessment (polls until complete by default)
cloudsecure --profile YOUR_PROFILE assess \
  --account-id 123456789012 \
  --role-arn arn:aws:iam::123456789012:role/CloudSecureAssessmentRole \
  --external-id your-external-id

# List all assessments
cloudsecure --profile YOUR_PROFILE status

# Check specific assessment
cloudsecure --profile YOUR_PROFILE status <ASSESSMENT_ID>

# Download report (HTML opens in browser)
cloudsecure --profile YOUR_PROFILE report <ASSESSMENT_ID> --format html --open

# Export as JSON or CSV
cloudsecure --profile YOUR_PROFILE report <ASSESSMENT_ID> --format json -o report.json
```

### Customer Onboarding

Create an assessment role in the target account:

```bash
aws cloudformation deploy \
  --template-file onboarding/cloudformation/cloudsecure-role.yaml \
  --stack-name CloudSecure-AssessmentRole \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ExternalId=your-external-id
```

### Reports Location

After assessment completes, reports are stored in S3:
```
s3://cloudsecure-reports-ACCOUNT_ID-dev/assessments/ASSESSMENT_ID/
├── report.html    # Professional HTML report
├── report.json    # Full JSON export
└── report.csv     # CSV export for spreadsheets
```

## Documentation

- [Technical Specification](./docs/cloudsecure-assessment-platform-spec.md)
- [Implementation Progress](./IMPLEMENTATION.md)
- [Architecture Diagrams](./docs/diagrams/)
- [CLI Documentation](./cli/README.md)

## License

Apache-2.0 - See [LICENSE](./LICENSE)
