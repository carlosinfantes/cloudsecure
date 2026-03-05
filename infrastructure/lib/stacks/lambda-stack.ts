import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import { Construct } from 'constructs';
import * as path from 'path';

export interface LambdaStackProps extends cdk.StackProps {
  envName: string;
  assessmentsTable: dynamodb.ITable;
  findingsTable: dynamodb.ITable;
  contextTable: dynamodb.ITable;
  reportsBucket: s3.IBucket;
  encryptionKey: kms.IKey;
}

export class LambdaStack extends cdk.Stack {
  public readonly validateRoleLambda: lambda.Function;
  public readonly discoveryModuleLambda: lambda.Function;
  public readonly sharedLayer: lambda.LayerVersion;

  // Analyzer Lambdas
  public readonly iamAnalyzerLambda: lambda.Function;
  public readonly networkAnalyzerLambda: lambda.Function;
  public readonly s3AnalyzerLambda: lambda.Function;
  public readonly encryptionAnalyzerLambda: lambda.Function;
  public readonly cloudtrailAnalyzerLambda: lambda.Function;
  public readonly aggregateFindingsLambda: lambda.Function;

  // Prowler Scanner (Container-based Lambda) - optional when skipProwler=true
  public readonly prowlerScannerLambda?: lambda.DockerImageFunction;
  public readonly prowlerRepository?: ecr.IRepository;

  // AI & Reports (Sprint 5)
  public readonly aiSynthesisLambda: lambda.Function;
  public readonly reportGeneratorLambda: lambda.Function;

  // Native Service Puller (Sprint 6)
  public readonly nativeServicePullerLambda: lambda.Function;

  constructor(scope: Construct, id: string, props: LambdaStackProps) {
    super(scope, id, props);

    const {
      envName,
      assessmentsTable,
      findingsTable,
      contextTable,
      reportsBucket,
      encryptionKey,
    } = props;

    // Common Lambda configuration
    const pythonRuntime = lambda.Runtime.PYTHON_3_12;
    const lambdasPath = path.join(__dirname, '../../../lambdas');

    // IAM role for cross-account assume role
    const crossAccountAssumePolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:AssumeRole'],
      resources: ['arn:aws:iam::*:role/CloudSecure*'],
    });


    // Shared Lambda layer for common dependencies
    // Note: For local development without Docker, the layer is created from the shared directory
    // In CI/CD, the pipeline will build the layer with dependencies
    this.sharedLayer = new lambda.LayerVersion(this, 'SharedLayer', {
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'layer')),
      compatibleRuntimes: [pythonRuntime],
      description: 'CloudSecure shared Python modules',
    });

    // Validate Role Lambda
    this.validateRoleLambda = new lambda.Function(this, 'ValidateRoleLambda', {
      functionName: `cloudsecure-validate-role-${envName}`,
      runtime: pythonRuntime,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'validate_role')),
      layers: [this.sharedLayer],
      timeout: cdk.Duration.minutes(2),
      memorySize: 256,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant permissions to validate role lambda
    assessmentsTable.grantReadWriteData(this.validateRoleLambda);
    encryptionKey.grantEncryptDecrypt(this.validateRoleLambda);
    this.validateRoleLambda.addToRolePolicy(crossAccountAssumePolicy);

    // Discovery Module Lambda
    this.discoveryModuleLambda = new lambda.Function(this, 'DiscoveryModuleLambda', {
      functionName: `cloudsecure-discovery-module-${envName}`,
      runtime: pythonRuntime,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'discovery_module')),
      layers: [this.sharedLayer],
      timeout: cdk.Duration.minutes(10),
      memorySize: 512,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        FINDINGS_TABLE: findingsTable.tableName,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant permissions to discovery module lambda
    assessmentsTable.grantReadWriteData(this.discoveryModuleLambda);
    findingsTable.grantWriteData(this.discoveryModuleLambda);
    encryptionKey.grantEncryptDecrypt(this.discoveryModuleLambda);
    this.discoveryModuleLambda.addToRolePolicy(crossAccountAssumePolicy);

    // ==================== Analyzer Lambdas ====================

    // Common analyzer configuration
    const analyzerTimeout = cdk.Duration.minutes(10);
    const analyzerMemory = 512;
    const analyzerEnv = {
      ASSESSMENTS_TABLE: assessmentsTable.tableName,
      FINDINGS_TABLE: findingsTable.tableName,
      LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
    };

    // IAM Analyzer Lambda
    this.iamAnalyzerLambda = new lambda.Function(this, 'IAMAnalyzerLambda', {
      functionName: `cloudsecure-iam-analyzer-${envName}`,
      runtime: pythonRuntime,
      handler: 'iam_analyzer.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'analyzers')),
      layers: [this.sharedLayer],
      timeout: analyzerTimeout,
      memorySize: analyzerMemory,
      environment: analyzerEnv,
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });
    this.iamAnalyzerLambda.addToRolePolicy(crossAccountAssumePolicy);

    // Network Analyzer Lambda
    this.networkAnalyzerLambda = new lambda.Function(this, 'NetworkAnalyzerLambda', {
      functionName: `cloudsecure-network-analyzer-${envName}`,
      runtime: pythonRuntime,
      handler: 'network_analyzer.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'analyzers')),
      layers: [this.sharedLayer],
      timeout: analyzerTimeout,
      memorySize: analyzerMemory,
      environment: analyzerEnv,
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });
    this.networkAnalyzerLambda.addToRolePolicy(crossAccountAssumePolicy);

    // S3 Analyzer Lambda
    this.s3AnalyzerLambda = new lambda.Function(this, 'S3AnalyzerLambda', {
      functionName: `cloudsecure-s3-analyzer-${envName}`,
      runtime: pythonRuntime,
      handler: 's3_analyzer.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'analyzers')),
      layers: [this.sharedLayer],
      timeout: analyzerTimeout,
      memorySize: analyzerMemory,
      environment: analyzerEnv,
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });
    this.s3AnalyzerLambda.addToRolePolicy(crossAccountAssumePolicy);

    // Encryption Analyzer Lambda
    this.encryptionAnalyzerLambda = new lambda.Function(this, 'EncryptionAnalyzerLambda', {
      functionName: `cloudsecure-encryption-analyzer-${envName}`,
      runtime: pythonRuntime,
      handler: 'encryption_analyzer.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'analyzers')),
      layers: [this.sharedLayer],
      timeout: analyzerTimeout,
      memorySize: analyzerMemory,
      environment: analyzerEnv,
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });
    this.encryptionAnalyzerLambda.addToRolePolicy(crossAccountAssumePolicy);

    // CloudTrail Analyzer Lambda
    this.cloudtrailAnalyzerLambda = new lambda.Function(this, 'CloudTrailAnalyzerLambda', {
      functionName: `cloudsecure-cloudtrail-analyzer-${envName}`,
      runtime: pythonRuntime,
      handler: 'cloudtrail_analyzer.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'analyzers')),
      layers: [this.sharedLayer],
      timeout: analyzerTimeout,
      memorySize: analyzerMemory,
      environment: analyzerEnv,
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });
    this.cloudtrailAnalyzerLambda.addToRolePolicy(crossAccountAssumePolicy);

    // Aggregate Findings Lambda
    this.aggregateFindingsLambda = new lambda.Function(this, 'AggregateFindingsLambda', {
      functionName: `cloudsecure-aggregate-findings-${envName}`,
      runtime: pythonRuntime,
      handler: 'aggregate_findings.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'analyzers')),
      layers: [this.sharedLayer],
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: analyzerEnv,
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant permissions to aggregate findings lambda
    assessmentsTable.grantReadWriteData(this.aggregateFindingsLambda);
    findingsTable.grantReadWriteData(this.aggregateFindingsLambda);
    encryptionKey.grantEncryptDecrypt(this.aggregateFindingsLambda);

    // ==================== Prowler Scanner (Container-based Lambda) ====================
    // Prowler runs as a container-based Lambda function.
    // Container image is pre-built and pushed to ECR before CDK deploy.
    // Skip entirely when skipProwler=true (e.g., Docker not available).
    const skipProwler = this.node.tryGetContext('skipProwler') === 'true';

    if (!skipProwler) {
      // Import existing ECR Repository for Prowler Lambda image
      this.prowlerRepository = ecr.Repository.fromRepositoryName(
        this,
        'ProwlerRepository',
        `cloudsecure-prowler-${envName}`
      );

      // Prowler Scanner Lambda (Container-based) - uses pre-pushed ECR image
      this.prowlerScannerLambda = new lambda.DockerImageFunction(this, 'ProwlerScannerLambda', {
        functionName: `cloudsecure-prowler-scanner-${envName}`,
        code: lambda.DockerImageCode.fromEcr(this.prowlerRepository, {
          tagOrDigest: 'latest',
        }),
        timeout: cdk.Duration.minutes(15),
        memorySize: 3072,
        ephemeralStorageSize: cdk.Size.gibibytes(1),
        environment: {
          ASSESSMENTS_TABLE: assessmentsTable.tableName,
          FINDINGS_TABLE: findingsTable.tableName,
          LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
        },
        logRetention: logs.RetentionDays.ONE_MONTH,
        tracing: lambda.Tracing.ACTIVE,
        description: 'Prowler security scanner for CIS AWS benchmarks',
      });

      // Grant permissions to Prowler Lambda
      assessmentsTable.grantReadWriteData(this.prowlerScannerLambda);
      findingsTable.grantWriteData(this.prowlerScannerLambda);
      encryptionKey.grantEncryptDecrypt(this.prowlerScannerLambda);
      this.prowlerScannerLambda.addToRolePolicy(crossAccountAssumePolicy);
    }

    // ==================== AI & Reports (Sprint 5) ====================

    // Bedrock invoke policy
    const bedrockPolicy = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['bedrock:InvokeModel'],
      resources: ['arn:aws:bedrock:*::foundation-model/anthropic.*'],
    });

    // AI Synthesis Lambda
    this.aiSynthesisLambda = new lambda.Function(this, 'AISynthesisLambda', {
      functionName: `cloudsecure-ai-synthesis-${envName}`,
      runtime: pythonRuntime,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'ai_synthesis')),
      layers: [this.sharedLayer],
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        BEDROCK_MODEL_ID: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant permissions to AI Synthesis Lambda
    assessmentsTable.grantReadWriteData(this.aiSynthesisLambda);
    encryptionKey.grantEncryptDecrypt(this.aiSynthesisLambda);
    this.aiSynthesisLambda.addToRolePolicy(bedrockPolicy);

    // Report Generator Lambda
    this.reportGeneratorLambda = new lambda.Function(this, 'ReportGeneratorLambda', {
      functionName: `cloudsecure-report-generator-${envName}`,
      runtime: pythonRuntime,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'report_generator')),
      layers: [this.sharedLayer],
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        FINDINGS_TABLE: findingsTable.tableName,
        REPORTS_BUCKET: reportsBucket.bucketName,
        PRESIGNED_URL_EXPIRY: '3600',
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant permissions to Report Generator Lambda
    assessmentsTable.grantReadWriteData(this.reportGeneratorLambda);
    findingsTable.grantReadData(this.reportGeneratorLambda);
    reportsBucket.grantReadWrite(this.reportGeneratorLambda);
    encryptionKey.grantEncryptDecrypt(this.reportGeneratorLambda);

    // ==================== Native Service Puller (Sprint 6) ====================

    // Native Service Puller Lambda
    this.nativeServicePullerLambda = new lambda.Function(this, 'NativeServicePullerLambda', {
      functionName: `cloudsecure-native-service-puller-${envName}`,
      runtime: pythonRuntime,
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'native_service_puller')),
      layers: [this.sharedLayer],
      timeout: cdk.Duration.minutes(10),
      memorySize: 512,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
      tracing: lambda.Tracing.ACTIVE,
    });

    // Grant permissions to Native Service Puller Lambda
    assessmentsTable.grantReadWriteData(this.nativeServicePullerLambda);
    findingsTable.grantWriteData(this.nativeServicePullerLambda);
    encryptionKey.grantEncryptDecrypt(this.nativeServicePullerLambda);
    this.nativeServicePullerLambda.addToRolePolicy(crossAccountAssumePolicy);

    // Outputs
    new cdk.CfnOutput(this, 'ValidateRoleLambdaArn', {
      value: this.validateRoleLambda.functionArn,
      description: 'Validate Role Lambda ARN',
      exportName: `CloudSecure-ValidateRoleLambda-${envName}`,
    });

    new cdk.CfnOutput(this, 'DiscoveryModuleLambdaArn', {
      value: this.discoveryModuleLambda.functionArn,
      description: 'Discovery Module Lambda ARN',
      exportName: `CloudSecure-DiscoveryModuleLambda-${envName}`,
    });

    if (this.prowlerScannerLambda) {
      new cdk.CfnOutput(this, 'ProwlerScannerLambdaArn', {
        value: this.prowlerScannerLambda.functionArn,
        description: 'Prowler Scanner Lambda ARN',
        exportName: `CloudSecure-ProwlerScanner-${envName}`,
      });
    }

    if (this.prowlerRepository) {
      new cdk.CfnOutput(this, 'ProwlerRepositoryUri', {
        value: this.prowlerRepository.repositoryUri,
        description: 'Prowler ECR Repository URI',
        exportName: `CloudSecure-ProwlerRepository-${envName}`,
      });
    }

    new cdk.CfnOutput(this, 'AISynthesisLambdaArn', {
      value: this.aiSynthesisLambda.functionArn,
      description: 'AI Synthesis Lambda ARN',
      exportName: `CloudSecure-AISynthesisLambda-${envName}`,
    });

    new cdk.CfnOutput(this, 'ReportGeneratorLambdaArn', {
      value: this.reportGeneratorLambda.functionArn,
      description: 'Report Generator Lambda ARN',
      exportName: `CloudSecure-ReportGeneratorLambda-${envName}`,
    });

    new cdk.CfnOutput(this, 'NativeServicePullerLambdaArn', {
      value: this.nativeServicePullerLambda.functionArn,
      description: 'Native Service Puller Lambda ARN',
      exportName: `CloudSecure-NativeServicePullerLambda-${envName}`,
    });
  }
}
