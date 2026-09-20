import * as lambda from 'aws-cdk-lib/aws-lambda';

/**
 * Files that must never end up inside a Lambda package.
 *
 * Reports generated locally (cloudsecure-report.html/json/csv) contain real
 * account data and sit in the same directories as the handlers, so without
 * this they are uploaded with every deployment. Caches only bloat the asset
 * and change its hash on every build.
 *
 * Note: report_generator/templates/report.html is a template, not a report,
 * and must keep shipping — so the patterns match report file names, not *.html.
 */
export const LAMBDA_ASSET_EXCLUDES = [
  'cloudsecure-report.*',
  '__pycache__',
  '*.pyc',
  '.pytest_cache',
  '.ruff_cache',
  '.coverage',
  '*.log',
];

/** Lambda code from a local directory, without local artifacts. */
export function pythonLambdaCode(assetPath: string): lambda.AssetCode {
  return lambda.Code.fromAsset(assetPath, { exclude: LAMBDA_ASSET_EXCLUDES });
}
