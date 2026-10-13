import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  apiErrorMessage,
  humanizeErrorCode,
  invalidFieldsSummary,
} from '../../apps/web/react/src/lib/error-messages.ts';

function apiError(payload, message = 'Request failed (409).') {
  return Object.assign(new Error(message), { payload, status: 409 });
}

const PAUSED = 'AstraNull SOC has paused testing for this workspace, so this run was not started. Contact support for status.';

const EXPECTED_COPY = {
  no_fqdn_target:
    'DNS TXT ownership proof works only for hostname and URL targets. Prove an IP or TCP target through an origin relation on a verified hostname.',
  challenge_active:
    'A DNS TXT value is already active for this target. Publish it and choose Check now; you can issue a new value after it expires.',
  challenge_expired: 'This DNS TXT value expired before it was found. Issue a new record and publish the new value.',
  ownership_not_verified: 'Ownership is not verified for this target yet. Publish the DNS TXT record and choose Check now.',
  governed_authorization_mismatch: 'The schedule does not match the governed authorization.',
  missing_schedule_window: 'Choose a schedule window inside the customer-requested window.',
  kill_switch_active: PAUSED,
  tenant_kill_switch_active: PAUSED,
  review_notes_required: 'Enter the reason the customer will see before rejecting.',
  risk_acceptance_required: 'Enter a reason of at least 20 characters and a review date.',
  export_too_large: 'Too many audit events to export at once. Narrow the date range and try again.',
};

describe('error message copy contract', () => {
  for (const [code, copy] of Object.entries(EXPECTED_COPY)) {
    it(`maps ${code} to written copy`, () => {
      assert.equal(humanizeErrorCode(code), copy);
      assert.equal(apiErrorMessage(apiError({ error: code }), 'Action failed.'), copy);
    });
  }

  it('appends the governed schedule invalid_fields as a plain list', () => {
    const banner = apiErrorMessage(
      apiError({
        error: 'governed_authorization_mismatch',
        invalid_fields: [
          'scheduled_window.outside_requested_window',
          'scheduled_window',
          'valid_window.scheduled_window',
          'scheduled_window.scope_hash',
        ],
      }),
      'Schedule failed.',
    );
    assert.equal(
      banner,
      'The schedule does not match the governed authorization. Scheduled window is outside the customer-requested window; Scheduled window is invalid; Scheduled window is outside the authorization artifact validity; Scope changed since approval.',
    );
    assert.doesNotMatch(banner, /_/);
  });

  it('de-snakes unmapped invalid_fields entries and accepts {field} objects', () => {
    assert.equal(
      invalidFieldsSummary(['artifacts.soc_approval', { field: 'requested_window', reason: 'x' }, 'artifacts.soc_approval']),
      'Artifacts soc approval; Requested window.',
    );
    assert.equal(invalidFieldsSummary([]), '');
    assert.equal(invalidFieldsSummary(undefined), '');
    assert.equal(invalidFieldsSummary([null, 7, '']), '');
  });

  it('keeps the base banner unchanged when invalid_fields is empty or absent', () => {
    assert.equal(
      apiErrorMessage(apiError({ error: 'missing_schedule_window', invalid_fields: [] }), 'Schedule failed.'),
      EXPECTED_COPY.missing_schedule_window,
    );
    assert.equal(
      apiErrorMessage(apiError({ error: 'x', message: 'Window rejected', invalid_fields: ['scheduled_window'] }), 'Schedule failed.'),
      'Window rejected. Scheduled window is invalid.',
    );
  });

  it('never appends invalid_fields to fixed 5xx copy', () => {
    const err = Object.assign(new Error('Service is temporarily unavailable. Try again shortly.'), {
      status: 503,
      payload: { error: 'boom', invalid_fields: ['scheduled_window'] },
    });
    assert.equal(apiErrorMessage(err, 'Action failed.'), 'Service is temporarily unavailable. Try again shortly.');
  });
});
