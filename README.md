<p align="center">
  <h1 align="center">CloudSecure</h1>
  <p align="center">AI-powered AWS security assessment platform</p>
</p>

<p align="center">
  <a href="https://github.com/carlosinfantes/cloudsecure/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/version-1.0.0-green.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.12-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/CDK-TypeScript-orange.svg" alt="CDK">
  <img src="https://img.shields.io/badge/AI-Bedrock%20Claude-blueviolet.svg" alt="AI">
</p>

---

Agentless, serverless security assessment platform that scans any AWS account and delivers AI-synthesized findings — no credentials shared, no agents installed, no infrastructure to manage.

## The Problem

Traditional security tools (Prowler, ScoutSuite, Steampipe) run from an engineer's laptop:

- Long-lived credentials (access keys) required
- Credentials travel over the wire and get stored locally
- No audit trail of who ran what and when
- Scaling to multiple accounts = manual effort

## How CloudSecure Is Different

CloudSecure runs **100% serverless inside AWS**. No CLI, no laptops, no credentials to share.

- **Delegated access via IAM roles** — customers grant a read-only role via `STS AssumeRole` with `ExternalId`. No credentials exchanged, only trust delegated.
- **Fully serverless** — Lambda, Step Functions, DynamoDB, S3. Nothing to install, patch, or maintain.
- **AI-powered synthesis** — 7 analyzers run in parallel, Bedrock Claude synthesizes raw findings into prioritized, actionable intelligence.
- **Auditable by design** — every assessment tracked in DynamoDB with full execution trail through Step Functions.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   CloudSecure Platform                        │
│                                                              │
│  ┌──────────┐  ┌───────────────┐  ┌────────────────────────┐ │
│  │   API    │──│ Step Functions │──│   7 Lambda Analyzers   │ │
│  │ Gateway  │  │  Orchestrator  │  │   (parallel execution) │ │
│  └──────────┘  └───────────────┘  └────────────────────────┘ │
│       │               │                      │               │
│  ┌──────────┐  ┌───────────────┐  ┌────────────────────────┐ │
│  │ DynamoDB │  │   Bedrock     │  │    S3 Reports          │ │
│  │          │  │   Claude AI   │  │  (HTML/JSON/CSV)       │ │
│  └──────────┘  └───────────────┘  └────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                          │
                    STS AssumeRole
                     (read-only)
                          ▼
              ┌──────────────────────┐
              │   Customer Account   │
              │  (no agents needed)  │
              └──────────────────────┘
```

## Analyzers

| Analyzer | What It Checks |
|----------|---------------|
| **IAM** | Users, roles, policies, MFA, unused credentials, password policy |
| **Network** | Security groups, VPCs, Flow Logs, public exposure |
| **S3** | Public buckets, encryption, logging, versioning |
| **Encryption** | EBS, RDS, EFS encryption at rest |
| **CloudTrail** | Trail configuration, root usage, metric filters |
| **Native Services** | SecurityHub, GuardDuty, Config findings (if enabled) |
| **Prowler** | CIS AWS 1.4 benchmarks (17 critical checks) |

All analyzers run in parallel via Step Functions. Missing security services are reported as findings, not blockers.

## Compliance Mapping

Findings map to: **CIS AWS 1.4** · **NIST 800-53** · **ISO 27001** · **GDPR** · **SOC2**

## Quick Start

### Prerequisites

- Node.js 18+ / Python 3.12+ / Docker / AWS CLI configured

### Deploy

```bash
# Install CDK dependencies
cd infrastructure && npm install

# Bootstrap CDK (first time only)
npx cdk bootstrap aws://ACCOUNT_ID/REGION

# Build Lambda layer
cd ../lambdas
docker run --rm --entrypoint /bin/bash \
  -v "$(pwd)/layer:/layer" \
  public.ecr.aws/lambda/python:3.12 \
  -c "pip install pydantic jinja2 boto3 --target /layer/python/ --no-cache-dir"
cp -r shared analyzers layer/python/

# Deploy
cd ../infrastructure
npx cdk deploy --all --require-approval never
```

### Onboard a Customer Account

```bash
# Customer deploys a read-only role (CloudFormation)
aws cloudformation create-stack \
  --stack-name CloudSecureRole \
  --template-body file://onboarding/cloudformation/cloudsecure-role.yaml \
  --parameters \
    ParameterKey=CloudSecureAccountId,ParameterValue=YOUR_ACCOUNT_ID \
    ParameterKey=ExternalId,ParameterValue=your-external-id \
  --capabilities CAPABILITY_NAMED_IAM
```

### Run an Assessment

```bash
ASSESSMENT_ID=$(uuidgen)
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:REGION:ACCOUNT_ID:stateMachine:cloudsecure-assessment \
  --input "{
    \"assessmentId\": \"$ASSESSMENT_ID\",
    \"accountId\": \"TARGET_ACCOUNT_ID\",
    \"roleArn\": \"arn:aws:iam::TARGET_ACCOUNT_ID:role/CloudSecureAssessmentRole\",
    \"externalId\": \"your-external-id\"
  }"
```

### Reports

```
s3://cloudsecure-reports-ACCOUNT_ID/assessments/ASSESSMENT_ID/
├── report.html    # Executive report with AI synthesis
├── report.json    # Full findings export
└── report.csv     # Spreadsheet format
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Infrastructure | AWS CDK (TypeScript) |
| Analyzers | Python 3.12 (Lambda) |
| Orchestration | AWS Step Functions |
| API | API Gateway REST |
| Database | DynamoDB |
| Storage | S3 + KMS encryption |
| AI Synthesis | AWS Bedrock (Claude) |
| Security Scanner | Prowler 5.x (Lambda container) |

## Documentation

- [Technical Specification](./cloudsecure-assessment-platform-spec.md)
- [Implementation Progress](./IMPLEMENTATION.md)
- [Contributing](./CONTRIBUTING.md)

## License

Apache-2.0 — See [LICENSE](./LICENSE)
