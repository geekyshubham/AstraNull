import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { cloudflareProvider } from '../../src/lib/connectorProviders/cloudflare.mjs';
import { TARGET_DETAIL_SHAPE } from '../helpers/portal-schema.mjs';

/**
 * G05: keep PROGRESS.md and the docs in step with what the code actually ships, so the
 * tracker never lists finished work as pending (or the reverse).
 */

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
const progress = read('PROGRESS.md');

function trackerRow(id) {
  const row = progress.split('\n').find((line) => line.includes(`| ${id} |`));
  assert.ok(row, `${id} row exists in PROGRESS.md`);
  return row;
}

describe('progress and docs reconciliation (G05)', () => {
  it('RUX-014 matches the shipped Cloudflare least-privilege scopes', () => {
    assert.deepEqual(cloudflareProvider.required_scopes, ['Zone > Zone > Read', 'Zone > WAF > Read (optional, rulesets)']);
    const row = trackerRow('RUX-014');
    assert.doesNotMatch(row, /still says `Zone:Read`/);
    assert.match(row, /Zone > Zone > Read/);
  });

  it('RUX-015 does not list the Teams notice or rule lifecycle as missing', () => {
    const notice = read('THIRD_PARTY_NOTICES/provider-logos-NOTICE.txt');
    assert.match(notice, /Microsoft Teams: the Teams product icon/);
    const row = trackerRow('RUX-015');
    assert.doesNotMatch(row, /Teams Fluent icon needs a `THIRD_PARTY_NOTICES` entry/);
    assert.doesNotMatch(row, /no test-send, update, or delete endpoint/);
    assert.match(row, /PATCH`\/`DELETE \/v1\/notifications\/:id/);
    // Still-open boundaries stay visible and the row is not marked complete.
    assert.match(row, /^\| \[~\] \|/);
    assert.match(row, /HMAC/);
  });

  it('RUX-015 cites the checked-in notification browser journey instead of calling it missing', () => {
    const row = trackerRow('RUX-015');
    assert.ok(existsSync(new URL('../e2e/journeys/portal-notification-channels.spec.mjs', import.meta.url)));
    assert.doesNotMatch(row, /no checked-in browser journey/);
    assert.match(row, /portal-notification-channels\.spec\.mjs/);
  });

  it('RUX-017 records the follow-up notification fixes and ADR-0010', () => {
    const row = trackerRow('RUX-017');
    for (const id of ['R01', 'R02', 'R03', 'R04']) {
      assert.match(row, new RegExp(`\\b${id}\\b`), `${id} is tracked`);
    }
    assert.ok(existsSync(new URL('../../docs/adr/0010-notification-delivery-leases-and-outbox-reconciliation.md', import.meta.url)));
    assert.match(row, /ADR-0010/);
    assert.doesNotMatch(row, /Retry-scheduler recovery of outbox rows still needs explicit tenant ids/);
  });

  it('RUX-016 no longer reports the target-tags contract gate as red', () => {
    assert.deepEqual(TARGET_DETAIL_SHAPE.target.tags, ['string']);
    const row = trackerRow('RUX-016');
    assert.doesNotMatch(row, /FT-SHAPE-01 fails/);
    assert.match(row, /ADR-0009/);
  });

  it('tracks every review item and keeps the reconciliation in progress while release limits remain', () => {
    const row = trackerRow('RUX-017');
    for (const id of ['F01', 'F02', 'F03', 'F04', 'F05', 'F06', 'F07', 'F08', 'F09', 'F10', 'F11', 'F12', 'G01', 'G02', 'G03', 'G04', 'G05']) {
      assert.match(row, new RegExp(`\\b${id}\\b`), `${id} is tracked`);
    }
    assert.match(row, /^\| \[~\] \|/);
    assert.match(row, /live-provider drills/);
  });

  it('lists only G03 browser journeys that are checked in', () => {
    const row = trackerRow('RUX-017');
    const specs = [...row.matchAll(/`(portal-[a-z0-9-]+\.spec\.mjs)`/g)].map((match) => match[1]);
    for (const spec of [
      'portal-trend-chart-refresh.spec.mjs',
      'portal-notification-channels.spec.mjs',
      'portal-refined-findings-groups.spec.mjs',
      'portal-refined-policies-runs.spec.mjs',
    ]) {
      assert.ok(specs.includes(spec), `${spec} is listed`);
    }
    for (const spec of specs) {
      assert.ok(existsSync(new URL(`../e2e/journeys/${spec}`, import.meta.url)), `${spec} exists`);
    }
    assert.doesNotMatch(row, /G03 open/);
  });

  it('documents target.tags in the target-detail spec without the removed agent binding', () => {
    const spec = read('docs/ux/16-portal-revamp-backend-spec.md');
    const section = spec.slice(spec.indexOf('### 4.1 `GET /v1/targets/:id`'), spec.indexOf('### 4.2'));
    assert.match(section, /"tags": \[/);
    assert.doesNotMatch(section, /"agent_binding"/);
  });

  it('documents the notification subscription and outbox behavior that ships', () => {
    const channels = read('docs/integrations/04-notification-channels.md');
    assert.doesNotMatch(channels, /^.*Events are only recorded for tenants with an enabled rule on that trigger\.$/m);
    assert.match(channels, /0060_notification_event_outbox\.sql/);
    const backend = read('docs/backend/07-notifications.md');
    assert.match(backend, /### Durable outbox for run and report triggers/);
    assert.match(backend, /uniq_notification_events_dedupe/);
  });
});
