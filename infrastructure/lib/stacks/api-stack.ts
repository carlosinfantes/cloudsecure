import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';
import * as path from 'path';

export interface ApiStackProps extends cdk.StackProps {
  envName: string;
  assessmentsTable: dynamodb.ITable;
  findingsTable: dynamodb.ITable;
  contextTable: dynamodb.ITable;
  reportsBucket: s3.IBucket;
  encryptionKey: kms.IKey;
  stateMachine: sfn.IStateMachine;
  sharedLayer: lambda.ILayerVersion;
}

export class ApiStack extends cdk.Stack {
  public readonly api: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const {
      envName,
      assessmentsTable,
      findingsTable,
      contextTable,
      reportsBucket,
      encryptionKey,
      stateMachine,
      sharedLayer,
    } = props;

    const lambdasPath = path.join(__dirname, '../../../lambdas');

    // API Gateway REST API
    this.api = new apigateway.RestApi(this, 'CloudSecureApi', {
      restApiName: `cloudsecure-api-${envName}`,
      description: 'CloudSecure Assessment Platform API',
      deployOptions: {
        stageName: envName,
        throttlingBurstLimit: 100,
        throttlingRateLimit: 50,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: envName !== 'prod',
        metricsEnabled: true,
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization', 'X-Amz-Date', 'X-Api-Key'],
      },
      endpointConfiguration: {
        types: [apigateway.EndpointType.REGIONAL],
      },
    });

    // Common Lambda configuration
    const pythonRuntime = lambda.Runtime.PYTHON_3_12;

    // ==================== API Lambda Functions ====================

    // Start Assessment Lambda
    const startAssessmentLambda = new lambda.Function(this, 'StartAssessmentLambda', {
      functionName: `cloudsecure-start-assessment-${envName}`,
      runtime: pythonRuntime,
      handler: 'start_assessment.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'api_handlers')),
      layers: [sharedLayer],
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        STATE_MACHINE_ARN: stateMachine.stateMachineArn,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
    });

    assessmentsTable.grantReadWriteData(startAssessmentLambda);
    stateMachine.grantStartExecution(startAssessmentLambda);
    encryptionKey.grantEncryptDecrypt(startAssessmentLambda);

    // Get Assessment Lambda
    const getAssessmentLambda = new lambda.Function(this, 'GetAssessmentLambda', {
      functionName: `cloudsecure-get-assessment-${envName}`,
      runtime: pythonRuntime,
      handler: 'get_assessment.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'api_handlers')),
      layers: [sharedLayer],
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
    });

    assessmentsTable.grantReadData(getAssessmentLambda);
    encryptionKey.grantDecrypt(getAssessmentLambda);

    // List Assessments Lambda
    const listAssessmentsLambda = new lambda.Function(this, 'ListAssessmentsLambda', {
      functionName: `cloudsecure-list-assessments-${envName}`,
      runtime: pythonRuntime,
      handler: 'list_assessments.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'api_handlers')),
      layers: [sharedLayer],
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
    });

    assessmentsTable.grantReadData(listAssessmentsLambda);
    encryptionKey.grantDecrypt(listAssessmentsLambda);

    // Get Report Lambda
    const getReportLambda = new lambda.Function(this, 'GetReportLambda', {
      functionName: `cloudsecure-get-report-${envName}`,
      runtime: pythonRuntime,
      handler: 'get_report.handler',
      code: lambda.Code.fromAsset(path.join(lambdasPath, 'api_handlers')),
      layers: [sharedLayer],
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      environment: {
        ASSESSMENTS_TABLE: assessmentsTable.tableName,
        REPORTS_BUCKET: reportsBucket.bucketName,
        LOG_LEVEL: envName === 'prod' ? 'INFO' : 'DEBUG',
      },
      logRetention: logs.RetentionDays.ONE_MONTH,
    });

    assessmentsTable.grantReadData(getReportLambda);
    reportsBucket.grantRead(getReportLambda);
    encryptionKey.grantDecrypt(getReportLambda);

    // ==================== API Gateway Integrations ====================

    // IAM Authorization
    const iamAuth = apigateway.AuthorizationType.IAM;

    // Lambda integrations
    const startAssessmentIntegration = new apigateway.LambdaIntegration(startAssessmentLambda);
    const getAssessmentIntegration = new apigateway.LambdaIntegration(getAssessmentLambda);
    const listAssessmentsIntegration = new apigateway.LambdaIntegration(listAssessmentsLambda);
    const getReportIntegration = new apigateway.LambdaIntegration(getReportLambda);

    // Mock integration for CRF endpoints (Phase 2 — not implemented in v1)
    const mockIntegration = new apigateway.MockIntegration({
      integrationResponses: [
        {
          statusCode: '501',
          responseTemplates: {
            'application/json': JSON.stringify({
              error: 'Not implemented in v1',
              status: 'not_implemented',
            }),
          },
        },
      ],
      requestTemplates: {
        'application/json': '{"statusCode": 501}',
      },
    });

    const methodOptions: apigateway.MethodOptions = {
      authorizationType: iamAuth,
    };

    const mockMethodOptions: apigateway.MethodOptions = {
      authorizationType: iamAuth,
      methodResponses: [{ statusCode: '501' }],
    };

    // ==================== Assessment Endpoints ====================
    const assessments = this.api.root.addResource('assessments');

    // POST /assessments - Trigger new assessment
    assessments.addMethod('POST', startAssessmentIntegration, {
      ...methodOptions,
      operationName: 'TriggerAssessment',
    });

    // GET /assessments - List assessments
    assessments.addMethod('GET', listAssessmentsIntegration, {
      ...methodOptions,
      operationName: 'ListAssessments',
    });

    const assessment = assessments.addResource('{assessmentId}');

    // GET /assessments/{assessmentId} - Get assessment status
    assessment.addMethod('GET', getAssessmentIntegration, {
      ...methodOptions,
      operationName: 'GetAssessment',
    });

    const report = assessment.addResource('report');

    // GET /assessments/{assessmentId}/report - Get assessment report
    report.addMethod('GET', getReportIntegration, {
      ...methodOptions,
      operationName: 'GetAssessmentReport',
    });

    // ==================== Context Endpoints (CRF) ====================
    const customers = this.api.root.addResource('customers');
    const customer = customers.addResource('{customerId}');
    const context = customer.addResource('context');

    // POST /customers/{customerId}/context - Create/update CRF entity
    context.addMethod('POST', mockIntegration, {
      ...mockMethodOptions,
      operationName: 'CreateContextEntity',
    });

    // GET /customers/{customerId}/context - List context entities
    context.addMethod('GET', mockIntegration, {
      ...mockMethodOptions,
      operationName: 'ListContextEntities',
    });

    const contextEntity = context.addResource('{entityId}');

    // GET /customers/{customerId}/context/{entityId} - Get specific entity
    contextEntity.addMethod('GET', mockIntegration, {
      ...mockMethodOptions,
      operationName: 'GetContextEntity',
    });

    // PUT /customers/{customerId}/context/{entityId} - Update entity
    contextEntity.addMethod('PUT', mockIntegration, {
      ...mockMethodOptions,
      operationName: 'UpdateContextEntity',
    });

    // DELETE /customers/{customerId}/context/{entityId} - Delete entity
    contextEntity.addMethod('DELETE', mockIntegration, {
      ...mockMethodOptions,
      operationName: 'DeleteContextEntity',
    });

    // ==================== Health Check ====================
    const health = this.api.root.addResource('health');
    health.addMethod('GET', new apigateway.MockIntegration({
      integrationResponses: [
        {
          statusCode: '200',
          responseTemplates: {
            'application/json': JSON.stringify({
              status: 'healthy',
              version: '1.0.0',
              environment: envName,
            }),
          },
        },
      ],
      requestTemplates: {
        'application/json': '{"statusCode": 200}',
      },
    }), {
      authorizationType: apigateway.AuthorizationType.NONE,
      methodResponses: [{ statusCode: '200' }],
      operationName: 'HealthCheck',
    });

    // Outputs
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: this.api.url,
      description: 'CloudSecure API endpoint URL',
      exportName: `CloudSecure-ApiEndpoint-${envName}`,
    });

    new cdk.CfnOutput(this, 'ApiId', {
      value: this.api.restApiId,
      description: 'CloudSecure API Gateway ID',
      exportName: `CloudSecure-ApiId-${envName}`,
    });
  }
}
