import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  deriveAwsV4SigningKey,
  signAwsJsonRequest,
} from '../../src/lib/connectorProviders/awsSigV4.mjs';

// AWS IAM ListUsers SigV4 example credentials/date/region/service. AWS publishes
// c4afb1cc...a4b9 as the derived aws4_request signing key for this vector.
const AWS_EXAMPLE_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';

describe('AWS SigV4 published vectors', () => {
  it('derives the published binary signing key rather than chaining hex text', () => {
    const key = deriveAwsV4SigningKey(
      AWS_EXAMPLE_SECRET,
      '20150830',
      'us-east-1',
      'iam',
    );
    assert.equal(Buffer.isBuffer(key), true);
    assert.equal(
      key.toString('hex'),
      'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9',
    );
  });

  it('sorts session-token headers canonically and signs a stable AWS WAF request', () => {
    const headers = signAwsJsonRequest({
      host: 'wafv2.us-east-1.amazonaws.com',
      region: 'us-east-1',
      service: 'wafv2',
      body: '{"Scope":"CLOUDFRONT","Limit":100}',
      credentials: {
        access_key_id: 'AKIDEXAMPLE',
        secret_access_key: AWS_EXAMPLE_SECRET,
        session_token: 'SESSIONTOKEN',
      },
      amzTarget: 'AWSWAF_20190729.ListWebACLs',
      now: new Date('2015-08-30T12:36:00.000Z'),
    });
    assert.equal(
      headers.authorization,
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/wafv2/aws4_request, '
      + 'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, '
      + 'Signature=43e659644407e651599fbee6c1e75e3c81265f457697ebc2d87d774bfa3820ec',
    );
  });
});
