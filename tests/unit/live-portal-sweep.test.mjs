import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  inspectVisibleLanguage,
  normalizedBaseUrl,
} from '../../scripts/live-portal-sweep.mjs';

describe('live portal sweep UX diagnostics', () => {
  it('flags visible machine codes and the requested developer jargon', () => {
    const result = inspectVisibleLanguage(
      'No WAF assets: coverage_summary_not_populated. Summary from API hydrator with canonical producer attribution.',
      '1440',
    );
    assert.deepEqual(result.machineTokens.map((entry) => entry.token), ['coverage_summary_not_populated']);
    assert.deepEqual(result.jargon.map((entry) => entry.kind), [
      'api',
      'hydrator',
      'canonical',
      'producer_attribution',
    ]);
    assert.equal(result.machineTokens[0].viewport, '1440');
    assert.match(result.machineTokens[0].snippet, /No WAF assets/);
  });

  it('excludes known record IDs and dotted check IDs without hiding standalone states', () => {
    const prefixes = ['tgt', 'tg', 'run', 'fnd', 'evt', 'agt', 'env', 'rpt', 'scan', 'usr', 'ten', 'wof', 'id', 'job', 'evd', 'btok', 'dns'];
    const text = `${prefixes.map((prefix) => `${prefix}_abc123`).join(' ')} origin.leak_scan.safe waf.api_surface_scan.safe must_block_before_origin`;
    const result = inspectVisibleLanguage(text);
    assert.deepEqual(result.machineTokens.map((entry) => entry.token), ['must_block_before_origin']);
  });

  it('pins production to the expected host while allowing HTTP loopback development', () => {
    assert.equal(normalizedBaseUrl('https://astranull.site'), 'https://astranull.site');
    assert.equal(normalizedBaseUrl('http://127.0.0.1:3000'), 'http://127.0.0.1:3000');
    assert.deepEqual(inspectVisibleLanguage('Check origin.leak_scan.safe.').machineTokens, []);
    for (const value of [
      'https://example.com',
      'https://astranull.site:444',
      'http://astranull.site',
      'https://astranull.site/path',
    ]) assert.throws(() => normalizedBaseUrl(value), /must be/);
  });

  it('keeps browser traffic GET-only and waits for visible loading placeholders', () => {
    const source = readFileSync(new URL('../../scripts/live-portal-sweep.mjs', import.meta.url), 'utf8');
    assert.match(source, /if \(request\.method\(\) !== 'GET'\)/);
    assert.match(source, /await route\.abort\('blockedbyclient'\)/);
    assert.match(source, /LOADING_SELECTOR/);
    assert.match(source, /horizontalOverflows/);
    assert.match(source, /style\.overflowX === 'auto'/);
  });
});
