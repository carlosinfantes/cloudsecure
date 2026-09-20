import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { StorageStack } from '../lib/stacks/storage-stack';
import { LambdaStack } from '../lib/stacks/lambda-stack';

function synthLambdaStack(): Template {
  const app = new cdk.App({ context: { skipProwler: true } });
  const storage = new StorageStack(app, 'TestStorage', { envName: 'test' });
  const lambdas = new LambdaStack(app, 'TestLambda', {
    envName: 'test',
    assessmentsTable: storage.assessmentsTable,
    findingsTable: storage.findingsTable,
    contextTable: storage.contextTable,
    reportsBucket: storage.reportsBucket,
    encryptionKey: storage.encryptionKey,
  });
  return Template.fromStack(lambdas);
}

/**
 * Functions that write findings. A missing FINDINGS_TABLE is not a deploy
 * error: the handler falls back to the dev table name, so a prod deployment
 * silently writes its findings into the dev table. That shipped once.
 */
const FINDINGS_WRITERS = [
  'cloudsecure-native-service-puller-test',
  'cloudsecure-discovery-module-test',
  'cloudsecure-iam-analyzer-test',
  'cloudsecure-network-analyzer-test',
  'cloudsecure-s3-analyzer-test',
  'cloudsecure-encryption-analyzer-test',
  'cloudsecure-cloudtrail-analyzer-test',
  'cloudsecure-aggregate-findings-test',
];

describe('LambdaStack environment', () => {
  test.each(FINDINGS_WRITERS)('%s receives FINDINGS_TABLE', (functionName) => {
    synthLambdaStack().hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: functionName,
      Environment: {
        Variables: Match.objectLike({
          FINDINGS_TABLE: Match.anyValue(),
        }),
      },
    });
  });

  test('every CloudSecure function knows the assessments table', () => {
    const template = synthLambdaStack();
    const functions = template.findResources('AWS::Lambda::Function');

    // CDK adds its own helper functions (log retention); only ours are named.
    const ours = Object.values(functions).filter((resource) =>
      String(resource.Properties?.FunctionName ?? '').startsWith('cloudsecure-'),
    );
    expect(ours.length).toBeGreaterThan(0);

    for (const resource of ours) {
      const variables = resource.Properties?.Environment?.Variables ?? {};
      expect({
        function: resource.Properties.FunctionName,
        variables: Object.keys(variables),
      }).toEqual({
        function: resource.Properties.FunctionName,
        variables: expect.arrayContaining(['ASSESSMENTS_TABLE']),
      });
    }
  });

  test('the Bedrock model is configurable through the environment', () => {
    synthLambdaStack().hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'cloudsecure-ai-synthesis-test',
      Environment: {
        Variables: Match.objectLike({ BEDROCK_MODEL_ID: Match.anyValue() }),
      },
    });
  });
});
