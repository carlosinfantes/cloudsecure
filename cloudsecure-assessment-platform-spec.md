# CloudSecure Assessment Platform - Technical Specification

**Version**: 1.0.0
**Status**: DRAFT
**Created**: 2025-01-23
**Author**: CloudSecure Contributors

---

## 1. Executive Summary

### 1.1 Vision
CloudSecure is an agentless, portable AWS security assessment platform that provides comprehensive security posture analysis regardless of what native AWS security services the customer has enabled. It combines open-source security tools (Prowler), custom analysis modules, and AI-powered synthesis (AWS Bedrock) to deliver actionable security insights.

### 1.2 Key Value Propositions
- **Agentless**: No software deployment required in customer accounts
- **Tool-Agnostic**: Works independently of customer's existing security tools
- **AI-Powered**: Bedrock Claude synthesizes findings into actionable intelligence
- **Compliance-Ready**: Maps to CIS, NIST 800-53, ISO 27001, GDPR, SOC2
- **Portable**: Can assess any AWS account with read permissions
- **Gap Detection**: Missing security services are findings, not blockers

### 1.3 Target Users
1. **Internal (Phase 1)**: Security team assessing managed accounts
2. **External (Phase 2)**: Other organizations seeking security assessments

---

## 2. Product Requirements

### 2.1 Functional Requirements

#### FR-001: Customer Onboarding
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-001.1 | System SHALL provide CloudFormation template for cross-account IAM role creation | P0 |
| FR-001.2 | System SHALL provide Terraform module for cross-account IAM role creation | P0 |
| FR-001.3 | System SHALL provide manual IAM role creation documentation | P0 |
| FR-001.4 | System SHALL validate IAM role permissions before assessment begins | P0 |
| FR-001.5 | System SHALL support single-account and multi-account (Organizations) assessments | P1 |

#### FR-002: Assessment Triggering
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-002.1 | System SHALL support on-demand assessment triggering via API | P0 |
| FR-002.2 | System SHALL accept assessment parameters (account ID, role ARN, scope) | P0 |
| FR-002.3 | System SHALL return assessment ID for tracking | P0 |
| FR-002.4 | System SHALL support assessment status polling | P0 |
| FR-002.5 | System SHALL support webhook notifications on completion | P2 |

#### FR-003: Discovery Module
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-003.1 | System SHALL enumerate all AWS regions with resources | P0 |
| FR-003.2 | System SHALL discover enabled security services (GuardDuty, SecurityHub, Config, Inspector, Macie, CloudTrail) | P0 |
| FR-003.3 | System SHALL document disabled/missing security services as findings | P0 |
| FR-003.4 | System SHALL inventory compute resources (EC2, Lambda, ECS, EKS) | P0 |
| FR-003.5 | System SHALL inventory storage resources (S3, EBS, EFS, RDS) | P0 |
| FR-003.6 | System SHALL inventory network resources (VPC, SG, NACL, IGW, NAT) | P0 |
| FR-003.7 | System SHALL inventory IAM resources (users, roles, policies, groups) | P0 |

#### FR-004: Prowler Integration
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-004.1 | System SHALL execute Prowler security checks against target account | P0 |
| FR-004.2 | System SHALL support CIS AWS Benchmark checks | P0 |
| FR-004.3 | System SHALL support NIST 800-53 checks | P1 |
| FR-004.4 | System SHALL support GDPR checks | P1 |
| FR-004.5 | System SHALL support SOC2 checks | P1 |
| FR-004.6 | System SHALL support custom check selection | P2 |
| FR-004.7 | System SHALL parse Prowler JSON output into normalized format | P0 |

#### FR-005: Custom Analysis Modules
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-005.1 | **IAM Analyzer**: Identify unused credentials (>90 days) | P0 |
| FR-005.2 | **IAM Analyzer**: Identify users without MFA | P0 |
| FR-005.3 | **IAM Analyzer**: Identify overprivileged roles (admin access) | P0 |
| FR-005.4 | **IAM Analyzer**: Identify cross-account trust relationships | P1 |
| FR-005.5 | **Network Analyzer**: Identify overly permissive security groups (0.0.0.0/0) | P0 |
| FR-005.6 | **Network Analyzer**: Identify public-facing resources | P0 |
| FR-005.7 | **Network Analyzer**: Check VPC Flow Logs enablement | P0 |
| FR-005.8 | **S3 Analyzer**: Identify public buckets | P0 |
| FR-005.9 | **S3 Analyzer**: Check encryption status | P0 |
| FR-005.10 | **S3 Analyzer**: Check access logging | P1 |
| FR-005.11 | **CloudTrail Analyzer**: Detect root account usage | P0 |
| FR-005.12 | **CloudTrail Analyzer**: Identify suspicious API patterns | P1 |
| FR-005.13 | **CloudTrail Analyzer**: Detect geographic anomalies | P2 |
| FR-005.14 | **Encryption Audit**: Identify unencrypted EBS volumes | P0 |
| FR-005.15 | **Encryption Audit**: Identify unencrypted RDS instances | P0 |

#### FR-006: Native Service Integration
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-006.1 | IF SecurityHub enabled, System SHALL pull aggregated findings | P1 |
| FR-006.2 | IF GuardDuty enabled, System SHALL pull threat findings | P1 |
| FR-006.3 | IF Config enabled, System SHALL pull compliance status | P1 |
| FR-006.4 | IF Inspector enabled, System SHALL pull vulnerability findings | P2 |
| FR-006.5 | System SHALL NOT fail if native services are disabled | P0 |

#### FR-007: AI Synthesis (Bedrock)
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-007.1 | System SHALL correlate related findings using Claude | P0 |
| FR-007.2 | System SHALL eliminate duplicate findings | P0 |
| FR-007.3 | System SHALL calculate risk scores (Critical/High/Medium/Low/Info) | P0 |
| FR-007.4 | System SHALL generate executive summary (1-2 pages) | P0 |
| FR-007.5 | System SHALL prioritize remediation actions | P0 |
| FR-007.6 | System SHALL map findings to compliance frameworks | P1 |
| FR-007.7 | System SHALL generate natural language remediation guidance | P0 |

#### FR-008: Report Generation
| ID | Requirement | Priority |
|----|-------------|----------|
| FR-008.1 | System SHALL generate PDF executive report | P0 |
| FR-008.2 | System SHALL generate JSON technical findings | P0 |
| FR-008.3 | System SHALL generate CSV findings export | P1 |
| FR-008.4 | System SHALL generate compliance mapping matrix | P1 |
| FR-008.5 | System SHALL store reports in S3 with configurable retention | P0 |
| FR-008.6 | System SHALL provide pre-signed URLs for report download | P0 |

### 2.2 Non-Functional Requirements

#### NFR-001: Performance
| ID | Requirement | Target |
|----|-------------|--------|
| NFR-001.1 | Single account assessment completion time | < 30 minutes |
| NFR-001.2 | Report generation time after findings collection | < 5 minutes |
| NFR-001.3 | Concurrent assessment support | 10 parallel assessments |

#### NFR-002: Security
| ID | Requirement |
|----|-------------|
| NFR-002.1 | All data in transit SHALL use TLS 1.2+ |
| NFR-002.2 | All data at rest SHALL be encrypted with KMS |
| NFR-002.3 | Customer credentials SHALL NOT be stored (STS AssumeRole only) |
| NFR-002.4 | Assessment results SHALL be isolated per customer |
| NFR-002.5 | API access SHALL require IAM authentication |
| NFR-002.6 | Audit trail SHALL log all assessment activities |

#### NFR-003: Reliability
| ID | Requirement | Target |
|----|-------------|--------|
| NFR-003.1 | Assessment success rate | > 99% |
| NFR-003.2 | Failed assessments SHALL be retryable | Yes |
| NFR-003.3 | Partial failures SHALL not abort entire assessment | Yes |

#### NFR-004: Scalability
| ID | Requirement |
|----|-------------|
| NFR-004.1 | System SHALL scale to assess 200+ accounts |
| NFR-004.2 | System SHALL use serverless architecture |
| NFR-004.3 | System SHALL not require capacity provisioning |

---

## 3. System Architecture

### 3.1 High-Level Architecture

```
                                    CloudSecure Assessment Platform
                                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                                    Deployment: Security Account (123456789012)
                                    Region: eu-west-1

┌──────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│   ┌─────────────┐         ┌─────────────────────────────────────────────────────┐   │
│   │  API        │         │              Step Functions Orchestrator             │   │
│   │  Gateway    │────────▶│                                                     │   │
│   │             │         │   ┌─────────┐    ┌─────────┐    ┌─────────┐        │   │
│   │  /assess    │         │   │Validate │───▶│Discovery│───▶│ Prowler │        │   │
│   │  /status    │         │   │  Role   │    │ Module  │    │ Scanner │        │   │
│   │  /report    │         │   └─────────┘    └─────────┘    └─────────┘        │   │
│   └─────────────┘         │        │              │              │              │   │
│                           │        │              ▼              ▼              │   │
│   ┌─────────────┐         │        │         ┌─────────────────────────┐       │   │
│   │  DynamoDB   │◀────────│────────┼────────▶│    Analysis Modules     │       │   │
│   │             │         │        │         │  ┌─────┐ ┌─────┐ ┌────┐ │       │   │
│   │  - Assess-  │         │        │         │  │ IAM │ │ S3  │ │Net │ │       │   │
│   │    ments    │         │        │         │  └─────┘ └─────┘ └────┘ │       │   │
│   │  - Findings │         │        │         │  ┌─────┐ ┌─────┐        │       │   │
│   │  - Status   │         │        │         │  │Trail│ │Crypt│        │       │   │
│   └─────────────┘         │        │         │  └─────┘ └─────┘        │       │   │
│                           │        │         └─────────────────────────┘       │   │
│   ┌─────────────┐         │        │                     │                     │   │
│   │  S3 Bucket  │         │        │                     ▼                     │   │
│   │             │◀────────│────────│─────────────────────┼──────────────────── │   │
│   │  - Reports  │         │        │         ┌─────────────────────────┐       │   │
│   │  - Raw Data │         │        │         │  Native Service Puller  │       │   │
│   │  - Prowler  │         │        │         │  (if available)         │       │   │
│   └─────────────┘         │        │         │  SecurityHub/GuardDuty  │       │   │
│                           │        │         │  Config/Inspector       │       │   │
│   ┌─────────────┐         │        │         └─────────────────────────┘       │   │
│   │  Bedrock    │         │        │                     │                     │   │
│   │  Claude 3.5 │◀────────│────────│─────────────────────┘                     │   │
│   │             │         │        │                                           │   │
│   │  - Synthesis│         │        ▼                                           │   │
│   │  - Reports  │         │   ┌─────────┐    ┌─────────┐    ┌─────────┐       │   │
│   └─────────────┘         │   │Aggregate│───▶│   AI    │───▶│ Report  │       │   │
│                           │   │Findings │    │Synthesis│    │Generator│       │   │
│                           │   └─────────┘    └─────────┘    └─────────┘       │   │
│                           │                                                     │   │
│                           └─────────────────────────────────────────────────────┘   │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                            │
                                            │ STS AssumeRole
                                            ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                              Customer Account(s)                                     │
│                                                                                      │
│   ┌────────────────────────────────────────────────────────────────────────────┐    │
│   │  IAM Role: CloudSecureAssessmentRole                                       │    │
│   │                                                                            │    │
│   │  Trust Policy:                                                             │    │
│   │  {                                                                         │    │
│   │    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},                │    │
│   │    "Action": "sts:AssumeRole",                                            │    │
│   │    "Condition": {"StringEquals": {"sts:ExternalId": "<unique-id>"}}       │    │
│   │  }                                                                         │    │
│   │                                                                            │    │
│   │  Attached Policies:                                                        │    │
│   │  - arn:aws:iam::aws:policy/ReadOnlyAccess                                 │    │
│   │  - arn:aws:iam::aws:policy/SecurityAudit                                  │    │
│   └────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Specifications

#### 3.2.1 API Gateway
```yaml
Name: cloudsecure-api
Type: REST API
Authentication: IAM
Endpoints:
  POST /assessments:
    Description: Trigger new assessment
    Request:
      accountId: string (required)
      roleArn: string (required)
      externalId: string (required)
      scope: string[] (optional, default: all)
      complianceFrameworks: string[] (optional)
    Response:
      assessmentId: string
      status: "PENDING"
      createdAt: timestamp

  GET /assessments/{assessmentId}:
    Description: Get assessment status
    Response:
      assessmentId: string
      status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED"
      progress: number (0-100)
      startedAt: timestamp
      completedAt: timestamp (if completed)
      findingsCount: number
      errorMessage: string (if failed)

  GET /assessments/{assessmentId}/report:
    Description: Get assessment report
    QueryParams:
      format: "pdf" | "json" | "csv"
    Response:
      downloadUrl: string (pre-signed S3 URL)
      expiresAt: timestamp
```

#### 3.2.2 Step Functions State Machine
```yaml
Name: CloudSecureAssessmentOrchestrator
StartAt: ValidateRole

States:
  ValidateRole:
    Type: Task
    Resource: arn:aws:lambda:...:validate-role
    Next: Discovery
    Catch:
      - ErrorEquals: [InvalidRoleError]
        Next: FailAssessment

  Discovery:
    Type: Task
    Resource: arn:aws:lambda:...:discovery-module
    Next: ParallelAssessment

  ParallelAssessment:
    Type: Parallel
    Branches:
      - StartAt: RunProwler
        States:
          RunProwler:
            Type: Task
            Resource: arn:aws:lambda:...:prowler-scanner
            End: true
      - StartAt: AnalyzeIAM
        States:
          AnalyzeIAM:
            Type: Task
            Resource: arn:aws:lambda:...:iam-analyzer
            End: true
      - StartAt: AnalyzeNetwork
        States:
          AnalyzeNetwork:
            Type: Task
            Resource: arn:aws:lambda:...:network-analyzer
            End: true
      - StartAt: AnalyzeS3
        States:
          AnalyzeS3:
            Type: Task
            Resource: arn:aws:lambda:...:s3-analyzer
            End: true
      - StartAt: AnalyzeCloudTrail
        States:
          AnalyzeCloudTrail:
            Type: Task
            Resource: arn:aws:lambda:...:cloudtrail-analyzer
            End: true
      - StartAt: AnalyzeEncryption
        States:
          AnalyzeEncryption:
            Type: Task
            Resource: arn:aws:lambda:...:encryption-analyzer
            End: true
      - StartAt: PullNativeServices
        States:
          PullNativeServices:
            Type: Task
            Resource: arn:aws:lambda:...:native-service-puller
            End: true
    Next: AggregateFindings

  AggregateFindings:
    Type: Task
    Resource: arn:aws:lambda:...:aggregate-findings
    Next: AISynthesis

  AISynthesis:
    Type: Task
    Resource: arn:aws:lambda:...:ai-synthesis
    TimeoutSeconds: 300
    Next: GenerateReports

  GenerateReports:
    Type: Task
    Resource: arn:aws:lambda:...:report-generator
    Next: CompleteAssessment

  CompleteAssessment:
    Type: Task
    Resource: arn:aws:lambda:...:complete-assessment
    End: true

  FailAssessment:
    Type: Task
    Resource: arn:aws:lambda:...:fail-assessment
    End: true
```

#### 3.2.3 Lambda Functions

| Function | Runtime | Memory | Timeout | Description |
|----------|---------|--------|---------|-------------|
| validate-role | Python 3.12 | 256 MB | 30s | Validate cross-account role permissions |
| discovery-module | Python 3.12 | 512 MB | 120s | Enumerate resources and services |
| prowler-scanner | Python 3.12 | 2048 MB | 900s | Execute Prowler security checks |
| iam-analyzer | Python 3.12 | 512 MB | 300s | Analyze IAM configuration |
| network-analyzer | Python 3.12 | 512 MB | 300s | Analyze network security |
| s3-analyzer | Python 3.12 | 512 MB | 300s | Analyze S3 bucket security |
| cloudtrail-analyzer | Python 3.12 | 1024 MB | 300s | Analyze CloudTrail events |
| encryption-analyzer | Python 3.12 | 512 MB | 300s | Audit encryption status |
| native-service-puller | Python 3.12 | 512 MB | 300s | Pull findings from native services |
| aggregate-findings | Python 3.12 | 1024 MB | 120s | Aggregate and normalize findings |
| ai-synthesis | Python 3.12 | 1024 MB | 300s | Bedrock Claude synthesis |
| report-generator | Python 3.12 | 1024 MB | 300s | Generate PDF/JSON/CSV reports |
| complete-assessment | Python 3.12 | 256 MB | 30s | Mark assessment complete |
| fail-assessment | Python 3.12 | 256 MB | 30s | Handle assessment failure |

#### 3.2.4 DynamoDB Tables

**Table: Assessments**
```yaml
TableName: cloudsecure-assessments
PartitionKey: assessmentId (S)
Attributes:
  - assessmentId: string
  - accountId: string
  - status: string (PENDING | RUNNING | COMPLETED | FAILED)
  - progress: number
  - createdAt: string (ISO8601)
  - startedAt: string (ISO8601)
  - completedAt: string (ISO8601)
  - findingsCount: number
  - criticalCount: number
  - highCount: number
  - mediumCount: number
  - lowCount: number
  - reportS3Key: string
  - errorMessage: string
GSI:
  - accountId-index (accountId, createdAt)
TTL: expiresAt (90 days)
```

**Table: Findings**
```yaml
TableName: cloudsecure-findings
PartitionKey: assessmentId (S)
SortKey: findingId (S)
Attributes:
  - assessmentId: string
  - findingId: string
  - source: string (prowler | iam-analyzer | network-analyzer | ...)
  - severity: string (CRITICAL | HIGH | MEDIUM | LOW | INFO)
  - title: string
  - description: string
  - resourceType: string
  - resourceId: string
  - region: string
  - complianceFrameworks: string[] (CIS-1.4, NIST-800-53, ...)
  - remediation: string
  - aiEnhanced: boolean
  - correlatedWith: string[]
TTL: expiresAt (90 days)
```

#### 3.2.5 S3 Buckets

```yaml
Bucket: cloudsecure-reports-123456789012
Encryption: SSE-KMS
Versioning: Enabled
Lifecycle:
  - Transition to IA: 30 days
  - Transition to Glacier: 90 days
  - Expiration: 365 days
Structure:
  /assessments/{assessmentId}/
    - raw/
      - discovery.json
      - prowler-output.json
      - iam-findings.json
      - network-findings.json
      - s3-findings.json
      - cloudtrail-findings.json
      - encryption-findings.json
      - native-services.json
    - aggregated/
      - all-findings.json
      - synthesis.json
    - reports/
      - executive-report.pdf
      - technical-findings.json
      - findings-export.csv
      - compliance-matrix.xlsx
```

---

## 4. Data Models

### 4.1 Finding Schema (Normalized)
```json
{
  "findingId": "uuid",
  "assessmentId": "uuid",
  "source": "prowler | iam-analyzer | securityhub | guardduty | ...",
  "sourceId": "original-finding-id",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "title": "string",
  "description": "string (detailed)",
  "resourceType": "AWS::EC2::SecurityGroup | AWS::S3::Bucket | ...",
  "resourceArn": "arn:aws:...",
  "resourceId": "sg-12345 | bucket-name | ...",
  "region": "eu-west-1",
  "accountId": "123456789012",
  "complianceFrameworks": [
    {"framework": "CIS-AWS-1.4", "control": "2.1.1"},
    {"framework": "NIST-800-53", "control": "AC-6"}
  ],
  "remediation": {
    "description": "string",
    "steps": ["Step 1", "Step 2"],
    "automatable": true,
    "effort": "LOW | MEDIUM | HIGH"
  },
  "evidence": {
    "current": "0.0.0.0/0 ingress on port 22",
    "expected": "Restricted source IP ranges"
  },
  "aiEnhanced": {
    "riskContext": "string (AI explanation)",
    "businessImpact": "string",
    "correlatedFindings": ["finding-id-1", "finding-id-2"],
    "priorityScore": 85
  },
  "detectedAt": "ISO8601",
  "metadata": {}
}
```

### 4.2 Assessment Report Schema
```json
{
  "reportId": "uuid",
  "assessmentId": "uuid",
  "generatedAt": "ISO8601",
  "accountId": "123456789012",
  "accountAlias": "my-account",
  "assessmentScope": {
    "regions": ["eu-west-1", "us-east-1"],
    "services": ["all"],
    "complianceFrameworks": ["CIS-AWS-1.4", "NIST-800-53"]
  },
  "executiveSummary": {
    "overallScore": 72,
    "securityPosture": "NEEDS_IMPROVEMENT",
    "criticalFindings": 3,
    "highFindings": 12,
    "mediumFindings": 45,
    "lowFindings": 89,
    "infoFindings": 23,
    "topRisks": [
      "Publicly accessible S3 buckets containing sensitive data",
      "Root account used within last 30 days",
      "Multiple users without MFA enabled"
    ],
    "immediateActions": [
      "Enable MFA for all IAM users",
      "Restrict S3 bucket public access",
      "Rotate unused IAM credentials"
    ],
    "aiSummary": "string (2-3 paragraph executive summary)"
  },
  "securityGaps": {
    "disabledServices": [
      {"service": "GuardDuty", "recommendation": "Enable for threat detection"},
      {"service": "Macie", "recommendation": "Enable for sensitive data discovery"}
    ]
  },
  "complianceStatus": {
    "CIS-AWS-1.4": {"passed": 45, "failed": 12, "notApplicable": 8},
    "NIST-800-53": {"passed": 120, "failed": 34, "notApplicable": 15}
  },
  "findings": [...],
  "remediationRoadmap": {
    "phase1": {"title": "Critical (0-7 days)", "items": [...]},
    "phase2": {"title": "High (1-4 weeks)", "items": [...]},
    "phase3": {"title": "Medium (1-3 months)", "items": [...]}
  }
}
```

---

## 5. AI Integration Specification

### 5.1 Bedrock Configuration
```yaml
Model: anthropic.claude-3-sonnet-20240229-v1:0
Region: eu-west-1 (primary), us-east-1 (fallback)
InferenceParameters:
  maxTokens: 4096
  temperature: 0.3
  topP: 0.9
```

### 5.2 AI Prompts

#### 5.2.1 Finding Correlation Prompt
```
You are a cloud security expert analyzing AWS security findings.

Given the following findings from multiple sources, identify:
1. Related findings that share a common root cause
2. Duplicate findings from different tools
3. Findings that when combined indicate a larger security issue

For each correlation:
- Provide a correlation ID
- List the related finding IDs
- Explain the relationship
- Suggest unified remediation

Findings:
{findings_json}

Respond in JSON format:
{
  "correlations": [
    {
      "correlationId": "uuid",
      "findingIds": ["id1", "id2"],
      "relationship": "explanation",
      "unifiedRemediation": "steps"
    }
  ]
}
```

#### 5.2.2 Executive Summary Prompt
```
You are a cloud security consultant preparing an executive briefing.

Based on the following security assessment findings for AWS account {account_id}:

Assessment Summary:
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Top Findings:
{top_findings}

Disabled Security Services:
{disabled_services}

Write a 2-3 paragraph executive summary that:
1. Describes the overall security posture in business terms
2. Highlights the most significant risks and their potential business impact
3. Provides 3-5 prioritized recommendations for immediate action

Use clear, non-technical language suitable for C-level executives.
Avoid jargon. Focus on business risk and impact.
```

#### 5.2.3 Remediation Guidance Prompt
```
You are a cloud security engineer providing remediation guidance.

For the following security finding:
{finding_json}

Provide detailed remediation steps that include:
1. Prerequisites (permissions, tools needed)
2. Step-by-step instructions (CLI commands or console steps)
3. Verification steps to confirm remediation
4. Potential impact of the remediation
5. Rollback procedure if needed

Consider:
- This is for AWS account with {context}
- Minimize service disruption
- Follow AWS best practices

Format as structured JSON:
{
  "prerequisites": [],
  "steps": [],
  "verification": [],
  "impact": "",
  "rollback": []
}
```

---

## 6. Customer Onboarding Artifacts

### 6.1 CloudFormation Template
```yaml
# cloudsecure-role.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: IAM Role for CloudSecure Security Assessment

Parameters:
  ExternalId:
    Type: String
    Description: External ID provided by CloudSecure
    MinLength: 10

  CloudSecureAccountId:
    Type: String
    Default: '123456789012'
    Description: CloudSecure platform account ID

Resources:
  CloudSecureAssessmentRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CloudSecureAssessmentRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${CloudSecureAccountId}:root'
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
        - arn:aws:iam::aws:policy/SecurityAudit
      Tags:
        - Key: Purpose
          Value: CloudSecure Security Assessment
        - Key: ManagedBy
          Value: CloudSecure

Outputs:
  RoleArn:
    Description: ARN of the CloudSecure assessment role
    Value: !GetAtt CloudSecureAssessmentRole.Arn
    Export:
      Name: CloudSecureAssessmentRoleArn
```

### 6.2 Terraform Module
```hcl
# modules/cloudsecure-role/main.tf

variable "external_id" {
  type        = string
  description = "External ID provided by CloudSecure"
}

variable "cloudsecure_account_id" {
  type        = string
  default     = "123456789012"
  description = "CloudSecure platform account ID"
}

resource "aws_iam_role" "cloudsecure_assessment" {
  name = "CloudSecureAssessmentRole"

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

  tags = {
    Purpose   = "CloudSecure Security Assessment"
    ManagedBy = "CloudSecure"
  }
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.cloudsecure_assessment.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.cloudsecure_assessment.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

output "role_arn" {
  value       = aws_iam_role.cloudsecure_assessment.arn
  description = "ARN of the CloudSecure assessment role"
}
```

---

## 7. Development Phases

### Phase 1: Foundation (Weeks 1-8)
| Week | Deliverables |
|------|-------------|
| 1-2 | CDK project setup, CI/CD pipeline, base infrastructure |
| 3-4 | API Gateway, Step Functions skeleton, DynamoDB tables |
| 5-6 | Role validation Lambda, basic discovery module |
| 7-8 | Prowler integration (Lambda layer), initial test harness |

### Phase 2: Analysis Modules (Weeks 9-16)
| Week | Deliverables |
|------|-------------|
| 9-10 | IAM Analyzer module |
| 11-12 | Network Analyzer, S3 Analyzer modules |
| 13-14 | CloudTrail Analyzer, Encryption Audit modules |
| 15-16 | Native service puller, findings aggregation |

### Phase 3: AI Integration (Weeks 17-22)
| Week | Deliverables |
|------|-------------|
| 17-18 | Bedrock integration, finding correlation |
| 19-20 | Risk scoring, executive summary generation |
| 21-22 | Remediation guidance, compliance mapping |

### Phase 4: Reports & Polish (Weeks 23-28)
| Week | Deliverables |
|------|-------------|
| 23-24 | PDF report generation (executive report) |
| 25-26 | JSON/CSV exports, compliance matrix |
| 27-28 | Customer onboarding artifacts, documentation |

### Phase 5: Production (Weeks 29-32)
| Week | Deliverables |
|------|-------------|
| 29-30 | Security hardening, penetration testing |
| 31-32 | Internal pilot, bug fixes |

---

## 8. Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| **Infrastructure** | CDK (TypeScript) | Type-safe, native AWS, complex orchestration |
| **Lambda Runtime** | Python 3.12 | Prowler compatibility, boto3, security tooling ecosystem |
| **Orchestration** | Step Functions | Visual workflow, error handling, parallelism |
| **API** | API Gateway REST | IAM auth, throttling, usage plans |
| **Database** | DynamoDB | Serverless, scalable, TTL support |
| **Storage** | S3 + KMS | Encryption, lifecycle, pre-signed URLs |
| **AI** | Bedrock Claude 3.5 | Managed, secure, enterprise-ready |
| **Security Scanner** | Prowler 4.x | Comprehensive, actively maintained, multi-framework |
| **PDF Generation** | WeasyPrint (Lambda layer) | HTML to PDF, styling support |
| **CI/CD** | GitHub Actions | Familiar, CDK integration |
| **Monitoring** | CloudWatch | Native, integrated, cost-effective |

---

## 9. Security Considerations

### 9.1 Data Protection
- All findings encrypted at rest (KMS CMK)
- All API traffic over TLS 1.2+
- Customer credentials never stored (STS AssumeRole with ExternalId)
- Assessment data isolated per customer (partition key)
- Automatic data expiration (90-day TTL)

### 9.2 Access Control
- API authentication via IAM (SigV4)
- Least privilege Lambda execution roles
- Cross-account access only via explicit trust
- Audit logging of all assessment activities

### 9.3 Compliance
- SOC2 Type II controls applicable
- GDPR data processing considerations
- Data residency (eu-west-1 primary)

---

## 10. Cost Estimation (Monthly)

| Component | Estimate | Notes |
|-----------|----------|-------|
| Lambda | $50-200 | Depends on assessment frequency |
| Step Functions | $25-100 | State transitions |
| DynamoDB | $25-50 | On-demand, auto-scaling |
| S3 | $10-30 | Reports storage |
| Bedrock | $100-500 | Claude API calls (~$0.003/1K input, $0.015/1K output) |
| API Gateway | $10-25 | REST API calls |
| KMS | $5-10 | Key operations |
| **Total** | **$225-915** | For ~50 assessments/month |

---

## 11. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Assessment completion rate | > 99% | Completed / Triggered |
| Average assessment time | < 30 min | CloudWatch metrics |
| Finding accuracy | > 95% | Manual validation sample |
| Customer satisfaction | > 4.5/5 | Post-assessment survey |
| Time to remediation | -40% | Before/after comparison |

---

## 12. Open Questions / Future Considerations

1. **Multi-cloud support**: Extend to Azure/GCP?
2. **Continuous monitoring**: Scheduled recurring assessments?
3. **Integration**: SIEM/SOAR integrations?
4. **Dashboard**: Interactive web dashboard vs. reports only?
5. **Pricing model**: Per-assessment, subscription, account-based?
6. **White-labeling**: Allow partners to rebrand?

---

## Appendix A: Prowler Check Categories

| Category | Check Count | Priority |
|----------|-------------|----------|
| IAM | 45+ | P0 |
| S3 | 25+ | P0 |
| EC2 | 30+ | P0 |
| CloudTrail | 15+ | P0 |
| VPC | 20+ | P0 |
| RDS | 15+ | P1 |
| Lambda | 10+ | P1 |
| KMS | 10+ | P0 |
| Config | 5+ | P1 |
| CloudWatch | 10+ | P1 |

---

## Appendix B: Compliance Framework Mapping

| Framework | Controls Covered | Implementation |
|-----------|-----------------|----------------|
| CIS AWS Benchmark 1.4 | 95% | Prowler + custom |
| CIS AWS Benchmark 2.0 | 80% | Prowler |
| NIST 800-53 | 60% | Mapping layer |
| ISO 27001 | 50% | Mapping layer |
| GDPR | 40% | Custom checks |
| SOC2 | 60% | Prowler + mapping |

---

*End of Specification Document*
