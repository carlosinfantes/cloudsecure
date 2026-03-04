# CloudSecure Assessment Role - Terraform Module
#
# This module creates an IAM role that allows CloudSecure to perform
# read-only security assessments of your AWS account.

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0.0"
    }
  }
}

# -----------------------------------------------------------------------------
# IAM Role
# -----------------------------------------------------------------------------

resource "aws_iam_role" "cloudsecure" {
  name                 = var.role_name
  description          = "Read-only role for CloudSecure security assessments"
  permissions_boundary = var.permissions_boundary_arn != "" ? var.permissions_boundary_arn : null
  max_session_duration = var.max_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.cloudsecure_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Purpose   = "CloudSecure-Security-Assessment"
    ManagedBy = "Terraform"
  })
}

# -----------------------------------------------------------------------------
# AWS Managed Policy Attachments
# -----------------------------------------------------------------------------

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.cloudsecure.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.cloudsecure.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# -----------------------------------------------------------------------------
# Custom Security Services Policy
# -----------------------------------------------------------------------------

resource "aws_iam_role_policy" "security_services" {
  name = "CloudSecureSecurityAccess"
  role = aws_iam_role.cloudsecure.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # SecurityHub access
      {
        Sid    = "SecurityHubAccess"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:GetInsights",
          "securityhub:GetEnabledStandards",
          "securityhub:DescribeHub",
          "securityhub:DescribeStandards",
          "securityhub:DescribeStandardsControls"
        ]
        Resource = "*"
      },

      # GuardDuty access
      {
        Sid    = "GuardDutyAccess"
        Effect = "Allow"
        Action = [
          "guardduty:GetDetector",
          "guardduty:GetFindings",
          "guardduty:ListDetectors",
          "guardduty:ListFindings",
          "guardduty:GetFindingsStatistics"
        ]
        Resource = "*"
      },

      # AWS Config access
      {
        Sid    = "ConfigAccess"
        Effect = "Allow"
        Action = [
          "config:DescribeConfigRules",
          "config:DescribeConfigurationRecorders",
          "config:DescribeComplianceByConfigRule",
          "config:GetComplianceDetailsByConfigRule",
          "config:DescribeConfigRuleEvaluationStatus"
        ]
        Resource = "*"
      },

      # Access Analyzer access
      {
        Sid    = "AccessAnalyzerAccess"
        Effect = "Allow"
        Action = [
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings",
          "access-analyzer:GetFinding"
        ]
        Resource = "*"
      },

      # Inspector access
      {
        Sid    = "InspectorAccess"
        Effect = "Allow"
        Action = [
          "inspector2:ListFindings",
          "inspector2:GetFindingsReportStatus",
          "inspector2:ListCoverage"
        ]
        Resource = "*"
      },

      # Macie access
      {
        Sid    = "MacieAccess"
        Effect = "Allow"
        Action = [
          "macie2:GetMacieSession",
          "macie2:ListFindings",
          "macie2:GetFindings",
          "macie2:GetFindingStatistics"
        ]
        Resource = "*"
      },

      # Account information
      {
        Sid    = "AccountAccess"
        Effect = "Allow"
        Action = [
          "account:GetAlternateContact",
          "account:GetContactInformation"
        ]
        Resource = "*"
      },

      # EKS access
      {
        Sid    = "EKSAccess"
        Effect = "Allow"
        Action = [
          "eks:ListClusters",
          "eks:DescribeCluster",
          "eks:ListNodegroups",
          "eks:DescribeNodegroup",
          "eks:ListAddons",
          "eks:DescribeAddon",
          "eks:ListFargateProfiles",
          "eks:DescribeFargateProfile",
          "eks:DescribeUpdate",
          "eks:ListTagsForResource"
        ]
        Resource = "*"
      },

      # Organizations read access
      {
        Sid    = "OrganizationsAccess"
        Effect = "Allow"
        Action = [
          "organizations:DescribeOrganization",
          "organizations:DescribeAccount",
          "organizations:ListAccounts",
          "organizations:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}
