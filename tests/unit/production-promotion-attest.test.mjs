import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseArgs, runProductionPromotionAttest } from '../../scripts/production-promotion-attest.mjs';

describe('production promotion attest', () => {
  it('parseArgs reads profile and base-url flags', () => {
    const opts = parseArgs(['--profile', 'hosted', '--base-url', 'https://staging.example.test']);
    assert.equal(opts.profile, 'hosted');
    assert.equal(opts.baseUrl, 'https://staging.example.test');
    assert.equal(opts.help, false);
  });

  it('requires base URL before running attest orchestration', async () => {
    await assert.rejects(
      () => runProductionPromotionAttest({ baseUrl: '' }),
      /ASTRANULL_HOSTED_STAGING_BASE_URL or --base-url is required/,
    );
  });

  it('parseArgs sets help when -h is passed', () => {
    const opts = parseArgs(['-h']);
    assert.equal(opts.help, true);
  });
});