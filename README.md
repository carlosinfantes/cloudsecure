# CloudSecure Assessment Platform

An agentless, portable AWS security assessment platform that provides comprehensive security posture analysis regardless of what native AWS security services the customer has enabled.

## Overview

CloudSecure combines open-source security tools (Prowler), custom analysis modules, and AI-powered synthesis (AWS Bedrock Claude) to deliver actionable security insights for AWS environments.

### Key Features

- **Agentless**: No software deployment required in customer accounts
- **Tool-Agnostic**: Works independently of customer's existing security tools
- **AI-Powered**: Bedrock Claude synthesizes findings into actionable intelligence
- **Compliance-Ready**: Maps to CIS AWS 1.4, NIST 800-53, ISO 27001, GDPR, SOC2
- **Portable**: Can assess any AWS account with read permissions
- **Gap Detection**: Missing security services are findings, not blockers

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
| PDF Generation | WeasyPrint (Future) |

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

- Node.js 18+
- Python 3.12+
- AWS CLI configured
- Docker (for Lambda layer builds)

### Quick Start

```bash
# 1. Install dependencies
cd infrastructure && npm install

# 2. Bootstrap CDK (first time only)
npx cdk bootstrap aws://ACCOUNT_ID/REGION

# 3. Build Lambda layer with correct Linux binaries
cd ../lambdas
docker run --rm --entrypoint /bin/bash \
  -v "$(pwd)/layer:/layer" \
  public.ecr.aws/lambda/python:3.12 \
  -c "pip install pydantic jinja2 boto3 --target /layer/python/ --no-cache-dir"
cp -r shared analyzers layer/python/

# 4. Deploy all stacks
cd ../infrastructure
npx cdk deploy --all --require-approval never

# 5. Create assessment role in target account
aws cloudformation create-stack \
  --stack-name CloudSecureRole \
  --template-body file://../onboarding/cloudformation/cloudsecure-role.yaml \
  --parameters \
    ParameterKey=CloudSecureAccountId,ParameterValue=ACCOUNT_ID \
    ParameterKey=ExternalId,ParameterValue=cloudsecure-test-12345 \
  --capabilities CAPABILITY_NAMED_IAM

# 6. Run assessment
ASSESSMENT_ID=$(uuidgen)
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:REGION:ACCOUNT_ID:stateMachine:cloudsecure-assessment-dev \
  --input "{
    \"assessmentId\": \"$ASSESSMENT_ID\",
    \"accountId\": \"ACCOUNT_ID\",
    \"roleArn\": \"arn:aws:iam::ACCOUNT_ID:role/CloudSecureAssessmentRole\",
    \"externalId\": \"cloudsecure-test-12345\"
  }"
```

### Deployment

```bash
# Development
cd infrastructure
npx cdk deploy --all --require-approval never

# Note: If Lambda layer updates fail with "export in use" error:
aws cloudformation delete-stack --stack-name CloudSecure-API-dev
aws cloudformation delete-stack --stack-name CloudSecure-Orchestration-dev
# Wait for deletion, then redeploy
npx cdk deploy --all --require-approval never
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

- [Technical Specification](./cloudsecure-assessment-platform-spec.md)
- [Implementation Progress](./IMPLEMENTATION.md)

## License

Apache-2.0 - See [LICENSE](./LICENSE)
