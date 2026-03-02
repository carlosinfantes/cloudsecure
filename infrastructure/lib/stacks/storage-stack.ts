import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

export interface StorageStackProps extends cdk.StackProps {
  envName: string;
}

export class StorageStack extends cdk.Stack {
  public readonly assessmentsTable: dynamodb.Table;
  public readonly findingsTable: dynamodb.Table;
  public readonly contextTable: dynamodb.Table;
  public readonly reportsBucket: s3.Bucket;
  public readonly encryptionKey: kms.Key;

  constructor(scope: Construct, id: string, props: StorageStackProps) {
    super(scope, id, props);

    const { envName } = props;

    // KMS Key for encryption
    this.encryptionKey = new kms.Key(this, 'EncryptionKey', {
      alias: `cloudsecure-key-${envName}`,
      description: 'CloudSecure encryption key for data at rest',
      enableKeyRotation: true,
      removalPolicy: envName === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Assessments Table
    this.assessmentsTable = new dynamodb.Table(this, 'AssessmentsTable', {
      tableName: `cloudsecure-assessments-${envName}`,
      partitionKey: { name: 'assessmentId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.encryptionKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: envName === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // GSI for querying by accountId
    this.assessmentsTable.addGlobalSecondaryIndex({
      indexName: 'accountId-index',
      partitionKey: { name: 'accountId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'createdAt', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Findings Table
    this.findingsTable = new dynamodb.Table(this, 'FindingsTable', {
      tableName: `cloudsecure-findings-${envName}`,
      partitionKey: { name: 'assessmentId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'findingId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.encryptionKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: envName === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // GSI for querying findings by severity
    this.findingsTable.addGlobalSecondaryIndex({
      indexName: 'severity-index',
      partitionKey: { name: 'assessmentId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'severity', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Context Table (CRF entities)
    this.contextTable = new dynamodb.Table(this, 'ContextTable', {
      tableName: `cloudsecure-context-${envName}`,
      partitionKey: { name: 'customerId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'entityId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.encryptionKey,
      pointInTimeRecovery: true,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: envName === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // GSI for querying context by entity type
    this.contextTable.addGlobalSecondaryIndex({
      indexName: 'entityType-index',
      partitionKey: { name: 'customerId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'entityType', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Reports S3 Bucket
    this.reportsBucket = new s3.Bucket(this, 'ReportsBucket', {
      bucketName: `cloudsecure-reports-${this.account}-${envName}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.encryptionKey,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: envName === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: envName !== 'prod',
      lifecycleRules: [
        {
          id: 'TransitionToIA',
          transitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: cdk.Duration.days(30),
            },
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: cdk.Duration.days(90),
            },
          ],
          expiration: cdk.Duration.days(365),
        },
      ],
    });

    // Outputs
    new cdk.CfnOutput(this, 'AssessmentsTableName', {
      value: this.assessmentsTable.tableName,
      description: 'DynamoDB table for assessments',
      exportName: `CloudSecure-AssessmentsTable-${envName}`,
    });

    new cdk.CfnOutput(this, 'FindingsTableName', {
      value: this.findingsTable.tableName,
      description: 'DynamoDB table for findings',
      exportName: `CloudSecure-FindingsTable-${envName}`,
    });

    new cdk.CfnOutput(this, 'ContextTableName', {
      value: this.contextTable.tableName,
      description: 'DynamoDB table for CRF context entities',
      exportName: `CloudSecure-ContextTable-${envName}`,
    });

    new cdk.CfnOutput(this, 'ReportsBucketName', {
      value: this.reportsBucket.bucketName,
      description: 'S3 bucket for assessment reports',
      exportName: `CloudSecure-ReportsBucket-${envName}`,
    });

    new cdk.CfnOutput(this, 'EncryptionKeyArn', {
      value: this.encryptionKey.keyArn,
      description: 'KMS key for encryption',
      exportName: `CloudSecure-EncryptionKey-${envName}`,
    });
  }
}
