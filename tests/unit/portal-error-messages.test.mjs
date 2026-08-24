import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  apiErrorMessage,
  humanizeErrorCode,
} from '../../apps/web/react/src/lib/error-messages.ts';

/**
 * Banner copy for backend error payloads.
 *
 * Surfaces rendered `payload?.message ?? payload?.error`, so any 4xx whose payload carried
 * only a code put that code in front of the customer verbatim — starting a run while another
 * was in flight showed the literal `concurrent_run_blocked`. The API contract is unchanged;
 * these tests pin the presentation layer that sits in front of it.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function apiError(payload, message = 'Request failed (409).') {
  return Object.assign(new Error(message), { payload });
}

describe('portal error humanizer', () => {
  it('replaces the observed concurrent_run_blocked code with actionable copy', () => {
    const banner = apiErrorMessage(apiError({ error: 'concurrent_run_blocked' }), 'Action failed.');
    assert.equal(
      banner,
      'A run is already in progress for this target group. Cancel or finalize it before starting another.',
    );
    assert.doesNotMatch(banner, /concurrent_run_blocked/);
  });

  it('never lets a snake_case code reach a banner, mapped or not', () => {
    const codes = [
      'concurrent_run_blocked',
      'target_group_not_found',
      'waf_retest_closure_not_ready',
      'outside_schedule_window',
      'invalid_discovery_transition',
      'postgres_route_not_wired',
      'connector_poll_failed',
      'not_found',
      'rate_limited',
    ];
    for (const code of codes) {
      const banner = apiErrorMessage(apiError({ error: code }), 'Action failed.');
      assert.doesNotMatch(banner, /_/, `${code} must not render with underscores`);
      assert.doesNotMatch(banner, /^[a-z]/, `${code} must render sentence-cased`);
      assert.match(banner, /[.!?]$/, `${code} must render as a sentence`);
    }
  });

  it('sentence-cases an unmapped code rather than inventing meaning', () => {
    assert.equal(humanizeErrorCode('some_new_backend_code'), 'Some new backend code.');
    assert.equal(humanizeErrorCode('waf-drift-detected'), 'Waf drift detected.');
    assert.equal(humanizeErrorCode('Already a sentence.'), 'Already a sentence.');
  });

  it('returns nothing for a code that is absent or not a string', () => {
    for (const value of [undefined, null, '', '   ', 42, {}, []]) {
      assert.equal(humanizeErrorCode(value), '');
    }
  });

  it('prefers a backend-authored message over the code, and never over-writes it', () => {
    const banner = apiErrorMessage(
      apiError({ error: 'connector_poll_failed', message: 'Outbound connector poll failed; manual metadata snapshots remain supported.' }),
      'Action failed.',
    );
    assert.equal(banner, 'Outbound connector poll failed; manual metadata snapshots remain supported.');
  });

  it('ignores a blank message and falls through to the code', () => {
    const banner = apiErrorMessage(apiError({ error: 'not_found', message: '   ' }), 'Action failed.');
    assert.equal(banner, 'That record no longer exists. Refresh and try again.');
  });

  it('falls back to the thrown message, then to the caller fallback', () => {
    assert.equal(
      apiErrorMessage(new Error('Service is temporarily unavailable. Try again shortly.'), 'Action failed.'),
      'Service is temporarily unavailable. Try again shortly.',
    );
    assert.equal(apiErrorMessage(apiError(null, ''), 'Cancel run failed.'), 'Cancel run failed.');
    assert.equal(apiErrorMessage(undefined, 'Cancel run failed.'), 'Cancel run failed.');
    assert.equal(apiErrorMessage({ not: 'an error' }, 'Cancel run failed.'), 'Cancel run failed.');
  });
});

describe('portal surfaces route errors through the humanizer', () => {
  it('no longer renders payload.error verbatim on the runs or settings surfaces', () => {
    for (const file of ['functional-surfaces.tsx', 'page-components.tsx']) {
      const source = readFileSync(path.join(ROOT, 'apps/web/react/src/pages', file), 'utf8');
      assert.doesNotMatch(
        source,
        /payload\?\.message \?\? payload\?\.error/,
        `${file} must extract banner text via apiErrorMessage`,
      );
      assert.match(source, /from '\.\.\/lib\/error-messages'/, `${file} must import the humanizer`);
    }
  });
});
