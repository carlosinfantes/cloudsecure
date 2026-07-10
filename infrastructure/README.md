# CloudSecure Infrastructure

AWS CDK (TypeScript) infrastructure for the CloudSecure Assessment Platform.

## Stacks

Deployed in dependency order:

| Stack | Name Pattern | Resources |
|-------|-------------|-----------|
| **Storage** | `CloudSecure-Storage-{env}` | DynamoDB tables (assessments, findings, context), S3 reports bucket (KMS encrypted), KMS key |
| **Lambda** | `CloudSecure-Lambda-{env}` | All Lambda functions, shared layer (Pydantic, Jinja2, analyzers), Prowler container image (ECR) |
| **Orchestration** | `CloudSecure-Orchestration-{env}` | Step Functions state machine (assessment workflow) |
| **API** | `CloudSecure-API-{env}` | API Gateway (REST, IAM auth), Lambda integrations |

## Commands

```bash
# From the repository root:
make install       # Install npm + Python dependencies
make build         # Compile TypeScript
make synth         # Synthesize CloudFormation templates
make deploy        # Build + deploy all stacks
make destroy       # Destroy all stacks (with confirmation)

# Or directly with CDK:
cd infrastructure
npx cdk synth      # Synthesize
npx cdk diff       # Compare with deployed
npx cdk deploy --all --profile <profile>
npx cdk destroy --all --profile <profile>
```

## Configuration

Stacks read configuration from CDK context and environment:

- **Environment name**: Set via `CLOUDSECURE_ENV` (default: `dev`)
- **Prowler**: Skip with `SKIP_PROWLER=true` or `-c skipProwler=true`
- **Region**: Defaults to `eu-west-1`

## Source Files

```
bin/cloudsecure.ts           # CDK app entry point
lib/stacks/storage-stack.ts  # DynamoDB, S3, KMS
lib/stacks/lambda-stack.ts   # Lambda functions + layer
lib/stacks/orchestration-stack.ts  # Step Functions
lib/stacks/api-stack.ts      # API Gateway
```
