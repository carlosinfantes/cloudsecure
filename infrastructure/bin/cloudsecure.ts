#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { StorageStack } from '../lib/stacks/storage-stack';
import { ApiStack } from '../lib/stacks/api-stack';
import { LambdaStack } from '../lib/stacks/lambda-stack';
import { OrchestrationStack } from '../lib/stacks/orchestration-stack';

const app = new cdk.App();

// Environment configuration
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || 'eu-west-1',
};

// Get environment name from context or default to 'dev'
const envName = app.node.tryGetContext('env') || 'dev';

// Storage Stack - DynamoDB, S3, KMS
const storageStack = new StorageStack(app, `CloudSecure-Storage-${envName}`, {
  env,
  envName,
  description: 'CloudSecure Assessment Platform - Storage Resources',
});

// Lambda Stack - Lambda functions
const lambdaStack = new LambdaStack(app, `CloudSecure-Lambda-${envName}`, {
  env,
  envName,
  assessmentsTable: storageStack.assessmentsTable,
  findingsTable: storageStack.findingsTable,
  contextTable: storageStack.contextTable,
  reportsBucket: storageStack.reportsBucket,
  encryptionKey: storageStack.encryptionKey,
  description: 'CloudSecure Assessment Platform - Lambda Functions',
});
lambdaStack.addDependency(storageStack);

// Orchestration Stack - Step Functions
const orchestrationStack = new OrchestrationStack(app, `CloudSecure-Orchestration-${envName}`, {
  env,
  envName,
  validateRoleLambda: lambdaStack.validateRoleLambda,
  discoveryModuleLambda: lambdaStack.discoveryModuleLambda,
  // Analyzer Lambdas
  iamAnalyzerLambda: lambdaStack.iamAnalyzerLambda,
  networkAnalyzerLambda: lambdaStack.networkAnalyzerLambda,
  s3AnalyzerLambda: lambdaStack.s3AnalyzerLambda,
  encryptionAnalyzerLambda: lambdaStack.encryptionAnalyzerLambda,
  cloudtrailAnalyzerLambda: lambdaStack.cloudtrailAnalyzerLambda,
  aggregateFindingsLambda: lambdaStack.aggregateFindingsLambda,
  // Prowler Scanner (Container Image)
  prowlerScannerLambda: lambdaStack.prowlerScannerLambda,
  // AI & Reports (Sprint 5)
  aiSynthesisLambda: lambdaStack.aiSynthesisLambda,
  reportGeneratorLambda: lambdaStack.reportGeneratorLambda,
  // Native Service Puller (Sprint 6)
  nativeServicePullerLambda: lambdaStack.nativeServicePullerLambda,
  description: 'CloudSecure Assessment Platform - Orchestration',
});
orchestrationStack.addDependency(lambdaStack);

// API Stack - API Gateway (depends on orchestration for state machine reference)
const apiStack = new ApiStack(app, `CloudSecure-API-${envName}`, {
  env,
  envName,
  assessmentsTable: storageStack.assessmentsTable,
  findingsTable: storageStack.findingsTable,
  contextTable: storageStack.contextTable,
  reportsBucket: storageStack.reportsBucket,
  encryptionKey: storageStack.encryptionKey,
  stateMachine: orchestrationStack.stateMachine,
  sharedLayer: lambdaStack.sharedLayer,
  description: 'CloudSecure Assessment Platform - API Resources',
});
apiStack.addDependency(orchestrationStack);

// Tags for all resources
cdk.Tags.of(app).add('Project', 'CloudSecure');
cdk.Tags.of(app).add('Environment', envName);
cdk.Tags.of(app).add('ManagedBy', 'CDK');
