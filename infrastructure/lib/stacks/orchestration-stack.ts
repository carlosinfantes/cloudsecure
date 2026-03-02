import * as cdk from 'aws-cdk-lib';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface OrchestrationStackProps extends cdk.StackProps {
  envName: string;
  validateRoleLambda: lambda.IFunction;
  discoveryModuleLambda: lambda.IFunction;
  // Analyzer Lambdas
  iamAnalyzerLambda: lambda.IFunction;
  networkAnalyzerLambda: lambda.IFunction;
  s3AnalyzerLambda: lambda.IFunction;
  encryptionAnalyzerLambda: lambda.IFunction;
  cloudtrailAnalyzerLambda: lambda.IFunction;
  aggregateFindingsLambda: lambda.IFunction;
  // Prowler Scanner (Container Image)
  prowlerScannerLambda: lambda.IFunction;
  // AI & Reports (Sprint 5)
  aiSynthesisLambda: lambda.IFunction;
  reportGeneratorLambda: lambda.IFunction;
  // Native Service Puller (Sprint 6)
  nativeServicePullerLambda: lambda.IFunction;
}

export class OrchestrationStack extends cdk.Stack {
  public readonly stateMachine: sfn.StateMachine;

  constructor(scope: Construct, id: string, props: OrchestrationStackProps) {
    super(scope, id, props);

    const {
      envName,
      validateRoleLambda,
      discoveryModuleLambda,
      iamAnalyzerLambda,
      networkAnalyzerLambda,
      s3AnalyzerLambda,
      encryptionAnalyzerLambda,
      cloudtrailAnalyzerLambda,
      aggregateFindingsLambda,
      prowlerScannerLambda,
      aiSynthesisLambda,
      reportGeneratorLambda,
      nativeServicePullerLambda,
    } = props;

    // Log group for state machine execution logs
    const logGroup = new logs.LogGroup(this, 'StateMachineLogGroup', {
      logGroupName: `/cloudsecure/${envName}/assessment-orchestrator`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ==================== Task Definitions ====================

    // Step 1: Validate Role
    const validateRoleTask = new tasks.LambdaInvoke(this, 'ValidateRole', {
      lambdaFunction: validateRoleLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Step 2: Discovery Module
    const discoveryTask = new tasks.LambdaInvoke(this, 'DiscoverResources', {
      lambdaFunction: discoveryModuleLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Step 3: Analyzer Tasks (run in parallel)
    const iamAnalyzerTask = new tasks.LambdaInvoke(this, 'IAMAnalyzer', {
      lambdaFunction: iamAnalyzerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    const networkAnalyzerTask = new tasks.LambdaInvoke(this, 'NetworkAnalyzer', {
      lambdaFunction: networkAnalyzerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    const s3AnalyzerTask = new tasks.LambdaInvoke(this, 'S3Analyzer', {
      lambdaFunction: s3AnalyzerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    const encryptionAnalyzerTask = new tasks.LambdaInvoke(this, 'EncryptionAnalyzer', {
      lambdaFunction: encryptionAnalyzerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    const cloudtrailAnalyzerTask = new tasks.LambdaInvoke(this, 'CloudTrailAnalyzer', {
      lambdaFunction: cloudtrailAnalyzerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Prowler Scanner Task (runs in parallel with other analyzers)
    const prowlerScannerTask = new tasks.LambdaInvoke(this, 'ProwlerScanner', {
      lambdaFunction: prowlerScannerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Native Service Puller Task (runs in parallel - Sprint 6)
    const nativeServicePullerTask = new tasks.LambdaInvoke(this, 'NativeServicePuller', {
      lambdaFunction: nativeServicePullerLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Parallel analyzers
    const parallelAnalyzers = new sfn.Parallel(this, 'RunAnalyzers', {
      resultPath: '$.analyzerResults',
    });

    parallelAnalyzers.branch(iamAnalyzerTask);
    parallelAnalyzers.branch(networkAnalyzerTask);
    parallelAnalyzers.branch(s3AnalyzerTask);
    parallelAnalyzers.branch(encryptionAnalyzerTask);
    parallelAnalyzers.branch(cloudtrailAnalyzerTask);
    parallelAnalyzers.branch(prowlerScannerTask);
    parallelAnalyzers.branch(nativeServicePullerTask);

    // Step 4: Aggregate Findings
    const aggregateFindingsTask = new tasks.LambdaInvoke(this, 'AggregateFindings', {
      lambdaFunction: aggregateFindingsLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Step 5: AI Synthesis (Sprint 5)
    const aiSynthesisTask = new tasks.LambdaInvoke(this, 'AISynthesis', {
      lambdaFunction: aiSynthesisLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // Step 6: Report Generation (Sprint 5)
    const reportGeneratorTask = new tasks.LambdaInvoke(this, 'GenerateReport', {
      lambdaFunction: reportGeneratorLambda,
      outputPath: '$.Payload',
      retryOnServiceExceptions: true,
    });

    // ==================== Error Handling States ====================

    const handleError = new sfn.Pass(this, 'HandleError', {
      parameters: {
        'error.$': '$.error',
        'assessmentId.$': '$.assessmentId',
        'status': 'FAILED',
      },
    });

    const roleValidationFailed = new sfn.Pass(this, 'RoleValidationFailed', {
      parameters: {
        'assessmentId.$': '$.assessmentId',
        'error.$': '$.error',
        'status': 'FAILED',
        'stage': 'VALIDATION',
      },
    });

    const discoveryFailed = new sfn.Pass(this, 'DiscoveryFailed', {
      parameters: {
        'assessmentId.$': '$.assessmentId',
        'error.$': '$.error',
        'status': 'FAILED',
        'stage': 'DISCOVERY',
      },
    });

    const assessmentComplete = new sfn.Pass(this, 'AssessmentComplete', {
      parameters: {
        'assessmentId.$': '$.assessmentId',
        'accountId.$': '$.accountId',
        'status': 'COMPLETED',
        'totalFindings.$': '$.totalFindings',
        'riskScore.$': '$.riskScore',
        'riskLevel.$': '$.riskLevel',
        'reportUrls.$': '$.reportUrls',
      },
    });

    // ==================== State Machine Definition ====================

    const definition = validateRoleTask
      .addCatch(handleError, { resultPath: '$.errorInfo' })
      .next(
        new sfn.Choice(this, 'IsRoleValid')
          .when(
            sfn.Condition.booleanEquals('$.valid', false),
            roleValidationFailed
          )
          .otherwise(
            discoveryTask
              .addCatch(handleError, { resultPath: '$.errorInfo' })
              .next(
                new sfn.Choice(this, 'IsDiscoverySuccessful')
                  .when(
                    sfn.Condition.booleanEquals('$.success', false),
                    discoveryFailed
                  )
                  .otherwise(
                    parallelAnalyzers
                      .addCatch(handleError, { resultPath: '$.errorInfo' })
                      .next(
                        aggregateFindingsTask
                          .addCatch(handleError, { resultPath: '$.errorInfo' })
                          .next(
                            new sfn.Choice(this, 'IsAggregationSuccessful')
                              .when(
                                sfn.Condition.booleanEquals('$.success', false),
                                handleError
                              )
                              .otherwise(
                                aiSynthesisTask
                                  .addCatch(handleError, { resultPath: '$.errorInfo' })
                                  .next(
                                    new sfn.Choice(this, 'IsAISynthesisSuccessful')
                                      .when(
                                        sfn.Condition.booleanEquals('$.success', false),
                                        handleError
                                      )
                                      .otherwise(
                                        reportGeneratorTask
                                          .addCatch(handleError, { resultPath: '$.errorInfo' })
                                          .next(
                                            new sfn.Choice(this, 'IsReportGenerationSuccessful')
                                              .when(
                                                sfn.Condition.booleanEquals('$.success', false),
                                                handleError
                                              )
                                              .otherwise(assessmentComplete)
                                          )
                                      )
                                  )
                              )
                          )
                      )
                  )
              )
          )
      );

    // Create state machine
    this.stateMachine = new sfn.StateMachine(this, 'AssessmentOrchestrator', {
      stateMachineName: `cloudsecure-assessment-${envName}`,
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      timeout: cdk.Duration.hours(2),
      tracingEnabled: true,
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
        includeExecutionData: true,
      },
    });

    // Outputs
    new cdk.CfnOutput(this, 'StateMachineArn', {
      value: this.stateMachine.stateMachineArn,
      description: 'Assessment Orchestrator State Machine ARN',
      exportName: `CloudSecure-StateMachine-${envName}`,
    });

    new cdk.CfnOutput(this, 'StateMachineName', {
      value: this.stateMachine.stateMachineName!,
      description: 'Assessment Orchestrator State Machine Name',
    });
  }
}
