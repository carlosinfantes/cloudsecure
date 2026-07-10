# CloudSecure

CLI for the **CloudSecure AWS Security Assessment Platform** — run security assessments, check status, and download reports from the command line.

## Installation

```bash
pip install cloudsecure
# or
pipx install cloudsecure
```

Requires Python 3.9+ and AWS credentials configured (`aws configure`).

## Quick Start

```bash
# Start a security assessment (scans everything)
cloudsecure assess \
  --account-id 123456789012 \
  --role-arn arn:aws:iam::123456789012:role/CloudSecureAssessmentRole \
  --external-id your-external-id

# Scan only specific services (iam, s3, network, encryption, cloudtrail, ec2, rds, vpc)
cloudsecure assess \
  --account-id 123456789012 \
  --role-arn arn:aws:iam::123456789012:role/CloudSecureAssessmentRole \
  --external-id your-external-id \
  --scope iam --scope s3

# List all assessments
cloudsecure status

# Check a specific assessment
cloudsecure status <ASSESSMENT_ID>

# Download report and open in browser
cloudsecure report <ASSESSMENT_ID> --format html --open
```

## Configuration

The CLI auto-discovers the API endpoint by querying CloudFormation stack outputs. You can also set it explicitly:

```bash
export CLOUDSECURE_API_ENDPOINT=https://abc123.execute-api.eu-west-1.amazonaws.com/prod
```

Options `--profile`, `--region`, and `--env` control which AWS profile and CloudSecure environment to use:

```bash
cloudsecure --profile my-profile --region eu-west-1 --env prod status
```

## Prerequisites

- **Python 3.9+**
- **AWS credentials** with access to the CloudSecure API Gateway
- **CloudSecure backend deployed** — see the [full repository](https://github.com/carlosinfantes/cloudsecure) for infrastructure deployment instructions

## License

Apache-2.0
