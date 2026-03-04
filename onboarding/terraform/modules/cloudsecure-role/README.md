# CloudSecure Assessment Role - Terraform Module

This Terraform module creates an IAM role that allows CloudSecure to perform read-only security assessments of your AWS account.

## Features

- Creates an IAM role with cross-account trust policy
- Attaches AWS managed policies: `ReadOnlyAccess` and `SecurityAudit`
- Adds custom policy for security service access (SecurityHub, GuardDuty, Config, etc.)
- Requires External ID for secure role assumption
- Supports optional permissions boundary

## Usage

```hcl
module "cloudsecure_role" {
  source = "path/to/modules/cloudsecure-role"

  cloudsecure_account_id = "123456789012"  # CloudSecure AWS Account ID
  external_id            = "your-external-id-from-cloudsecure"

  # Optional
  role_name                = "CloudSecureAssessmentRole"
  permissions_boundary_arn = ""
  max_session_duration     = 3600

  tags = {
    Environment = "production"
    Team        = "security"
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0.0 |
| aws | >= 4.0.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| cloudsecure_account_id | The AWS Account ID where CloudSecure is deployed | `string` | n/a | yes |
| external_id | The External ID provided by CloudSecure | `string` | n/a | yes |
| role_name | Name for the IAM role | `string` | `"CloudSecureAssessmentRole"` | no |
| permissions_boundary_arn | ARN of a permissions boundary policy | `string` | `""` | no |
| max_session_duration | Maximum session duration in seconds | `number` | `3600` | no |
| tags | Additional tags to apply | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| role_arn | ARN of the CloudSecure assessment role |
| role_name | Name of the CloudSecure assessment role |
| role_id | Unique ID of the CloudSecure assessment role |
| instructions | Next steps after deployment |

## Security

This role provides **read-only** access to your AWS account. It includes:

- AWS managed `ReadOnlyAccess` policy
- AWS managed `SecurityAudit` policy
- Custom policy for security service access

The role uses an **External ID** for secure cross-account access, preventing confused deputy attacks.

## Services Accessed

The role can read data from the following services:

- AWS SecurityHub
- Amazon GuardDuty
- AWS Config
- IAM Access Analyzer
- Amazon Inspector
- Amazon Macie
- Amazon EKS
- AWS Organizations (read-only)
- All services covered by ReadOnlyAccess and SecurityAudit policies
