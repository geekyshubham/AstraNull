import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  apiErrorMessage,
  configurationErrorMessage,
  humanizeErrorCode,
  publicApiErrorCode,
  publicApiErrorMessage,
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

  it('maps known 5xx configuration codes to fixed actionable copy without server text', () => {
    const err = Object.assign(new Error('Service is temporarily unavailable. Try again shortly.'), {
      status: 503,
      payload: { error: 'encryption_not_configured', message: 'internal detail host=db-7' },
    });
    const banner = apiErrorMessage(err, 'Action failed.');
    assert.match(banner, /ASTRANULL_SECRET_ENCRYPTION_KEY/);
    assert.doesNotMatch(banner, /db-7|encryption_not_configured/);
    assert.equal(configurationErrorMessage({ error: 'unknown_failure' }), '');
    const generic = Object.assign(new Error('Something went wrong on the server. Try again.'), {
      status: 500,
      payload: { error: 'boom', message: 'stack trace' },
    });
    assert.equal(apiErrorMessage(generic, 'Action failed.'), 'Something went wrong on the server. Try again.');
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

  it('ignores attached server messages for 5xx API failures', () => {
    const err = Object.assign(new Error('Something went wrong on the server. Try again.'), {
      status: 500,
      payload: {
        error: 'internal_error',
        message: 'relation tenant_secrets does not exist on db-primary.internal',
      },
    });
    const banner = apiErrorMessage(err, 'Action failed.');
    assert.equal(banner, 'Something went wrong on the server. Try again.');
    assert.doesNotMatch(banner, /tenant_secrets|db-primary/);
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

describe('public API error boundary', () => {
  it('uses fixed copy for known codes without trusting a supplied message', () => {
    assert.equal(
      publicApiErrorMessage(404, {
        error: 'not_found',
        message: 'proxy diagnostic: upstream route table missing',
      }, 'Lookup failed.'),
      'The requested record was not found.',
    );
    assert.equal(
      publicApiErrorMessage(400, {
        error: 'unknown_public_code',
        message: 'database relation public.users does not exist',
      }, 'Request failed. Try again.'),
      'Request failed. Try again.',
    );
  });

  it('collapses all 5xx payloads to fixed availability copy', () => {
    for (const status of [500, 502, 503, 504]) {
      assert.equal(
        publicApiErrorMessage(status, {
          error: 'internal_error',
          message: 'sensitive topology and schema diagnostic',
        }, 'Flow-specific fallback.'),
        'Service is temporarily unavailable. Try again.',
      );
    }
  });


  it('withholds known codes from caller-specific dispatch on every 5xx response', () => {
    const codes = [
      'invalid_credentials',
      'rate_limited',
      'duplicate_request',
      'weak_password',
      'mfa_required',
      'password_login_disabled',
    ];
    for (const status of [500, 502, 503, 504]) {
      for (const code of codes) {
        assert.equal(publicApiErrorCode(status, { error: code }), '');
      }
    }
    assert.equal(
      publicApiErrorCode(400, { error: 'invalid_credentials' }),
      'invalid_credentials',
      'documented 4xx codes must remain available for fixed flow-specific copy',
    );
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

  it('never renders server-authored message fields on public or auth surfaces', () => {
    const source = readFileSync(
      path.join(ROOT, 'apps/web/react/src/pages/public-pages.tsx'),
      'utf8',
    );
    assert.doesNotMatch(source, /json\.message/, 'public pages must not trust API message fields');
    assert.doesNotMatch(
      source,
      /String\(json\.error \?\? ['"][^'"]+/,
      'public pages must not use a raw API error code as fallback copy',
    );
    assert.doesNotMatch(
      source,
      /String\(json\.error/,
      'public pages must route code inspection through the status-aware boundary',
    );
    assert.equal(
      source.match(/publicApiErrorCode\((?:response\.status|status), json\)/g)?.length,
      6,
      'all six public/auth code dispatchers must suppress payload codes for 5xx responses',
    );
    assert.match(source, /publicApiErrorMessage/, 'public pages must use the fixed public boundary');
  });
});
