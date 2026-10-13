import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { activityIsLive, activityPath, captureWarnings, createActivityReaderKey, createRecordedActivityReader, mergeActivityItems, stopStateLabel } from '../../apps/web/react/src/lib/recorded-activity.mjs';
import { buildEvidenceInspectorHref, evidenceContextPath, normalizeEvidenceContext, normalizeInspectorRef, parseInspectorRef } from '../../apps/web/react/src/lib/evidence-inspector.mjs';
import { activityRequestLimitLabel, activityRequestsSentLabel, activityValueLabel } from '../../apps/web/react/src/lib/activity-labels.mjs';
import { generateCheckProbeLogs } from '../../apps/web/react/src/lib/live-probe-logs.mjs';

const event = (id, sequence = 1) => ({ id, sequence, at: `2026-10-08T10:00:0${sequence}.000Z`, stage: 'request_started', source: 'signed_worker', method: 'GET' });
const envelope = (items, extra = {}) => ({ run_id: 'r1', target_id: 't1', check_id: 'c1', status: 'collecting', items, ...extra });
const settle = async () => { for (let index = 0; index < 30; index += 1) await Promise.resolve(); };
function clock() {
  const queue = new Map(); let id = 0;
  return {
    schedule: (fn, ms) => { const key = ++id; queue.set(key, { fn, ms }); return key; },
    unschedule: (key) => queue.delete(key),
    delays: () => [...queue.values()].map((item) => item.ms),
    async tick(ms) { const next = [...queue.entries()].find(([, item]) => item.ms === ms); assert.ok(next, `no timer for ${ms}`); queue.delete(next[0]); await next[1].fn(); await settle(); },
  };
}
function reader(read, kind = 'run') { const timers = clock(); return { timers, stream: createRecordedActivityReader({ kind, id: 'r1', read, ...timers, now: () => '2026-10-08T10:10:00.000Z' }) }; }

test('exact assessment navigation remains ID-only and never calls an unsupported evidence route', () => {
  const ref = { entry: 'validation_scan', target_id: 't1', scan_id: 'scan_exact' };
  const href = buildEvidenceInspectorHref({ ...ref, token: 'secret', test_run_id: 'unrelated' }, '#target-detail?id=t1&tab=validate');
  assert.deepEqual(parseInspectorRef(href), ref);
  assert.equal(evidenceContextPath(ref), '');
  assert.equal(normalizeInspectorRef({ entry: 'validation_scan', target_id: 't1' }), null);
  assert.equal(activityPath('run', 'run:1', 'evt_cursor'), '/v1/test-runs/run%3A1/activity?limit=256&cursor=evt_cursor');
  assert.equal(activityPath('scan', 'scan:1', 'opaque_cursor'), '/v1/validation-scans/scan%3A1/activity?limit=256&after=opaque_cursor');
});

test('immutable event merge deduplicates replays without replacing earlier facts', () => {
  const first = event('one');
  assert.deepEqual(mergeActivityItems([first], [{ ...first, method: 'POST' }, event('two', 2)]), [first, event('two', 2)]);
});

test('reader drains pages, retains cursor across reconnect, and shares one stream with two displays', async () => {
  const paths = []; let fail = false;
  const { stream, timers } = reader(async (path) => {
    paths.push(path);
    if (fail) { fail = false; throw new Error('offline'); }
    if (!path.includes('cursor=')) return envelope([event('one')], { next_cursor: 'one', has_more: true, total_recorded: 2 });
    return envelope([event('one'), event('two', 2)], { next_cursor: 'two', has_more: false, total_recorded: 2 });
  });
  const first = stream.subscribe(() => {});
  const second = stream.subscribe(() => {});
  await settle();
  assert.equal(paths.length, 2, 'subscribers do not duplicate polling');
  assert.deepEqual(stream.getState().snapshot.items.map((row) => row.id), ['one', 'two']);
  fail = true;
  await timers.tick(2500);
  assert.equal(stream.getState().snapshot.items.length, 2, 'outage preserves previous records');
  assert.ok(stream.getState().error);
  await timers.tick(5000);
  assert.match(paths.at(-1), /cursor=two/);
  assert.equal(stream.getState().error, null);
  assert.equal(stream.getState().lastUpdated, '2026-10-08T10:10:00.000Z');
  first.unsubscribe(); second.unsubscribe(); stream.dispose();
});

test('nested modern pagination retains every page and uses opaque scan after cursors', async () => {
  const paths = [];
  const { stream } = reader(async (path) => {
    paths.push(path);
    if (!path.includes('/activity')) return { id: 'r1', status: 'running', steps: [] };
    const second = path.includes('after=');
    return { scan_id: 'r1', status: 'running', items: [event(second ? 'two' : 'one', second ? 2 : 1)], pagination: { next_cursor: second ? 'opaque_two' : 'opaque_one', has_more: !second, total_recorded: 2 } };
  }, 'scan');
  stream.subscribe(() => {}); await settle();
  assert.equal(paths.length, 3);
  assert.match(paths.at(-1), /after=opaque_one/);
  assert.deepEqual(stream.getState().snapshot.items.map((item) => item.id), ['one', 'two']);
  assert.ok(captureWarnings({ pagination: { has_more: true }, capture: { status: 'unknown' } }).some((warning) => /More recorded pages/.test(warning)));
  stream.dispose();
});

test('fast completion receives a final sweep and final evidence notification even without live status', async () => {
  let reads = 0; const revisions = [];
  const { stream, timers } = reader(async () => envelope(reads++ ? [event('final', 2)] : [event('initial')], { status: 'verdicted', next_cursor: reads === 1 ? 'initial' : 'final', has_more: false }));
  stream.subscribe((state) => revisions.push(state.revision));
  await settle();
  await timers.tick(2500);
  assert.deepEqual(stream.getState().snapshot.items.map((row) => row.id), ['initial', 'final']);
  assert.equal(stream.getState().revision, 2);
  assert.equal(timers.delays().length, 0, 'final reader stops after bounded final sweep');
  assert.ok(revisions.includes(2)); stream.dispose();
});

test('pause suspends only display subscription and never issues cancellation; resume retains events', async () => {
  let reads = 0;
  const { stream, timers } = reader(async () => { reads += 1; return envelope([event(`e${reads}`, reads)]); });
  let view;
  const subscription = stream.subscribe((state) => { view = state; });
  await settle();
  subscription.setActive(false);
  assert.equal(timers.delays().length, 0);
  assert.equal(reads, 1);
  subscription.setActive(true);
  await settle();
  assert.equal(reads, 2);
  assert.deepEqual(view.snapshot.items.map((row) => row.id), ['e1', 'e2']); stream.dispose();
});

test('delayed reads cannot commit after disposal or a paused generation', async () => {
  let resolve;
  const { stream } = reader(() => new Promise((done) => { resolve = done; }));
  let view;
  stream.subscribe((state) => { view = state; });
  stream.dispose(); resolve(envelope([event('late')])); await settle();
  assert.equal(view.snapshot, null);
  assert.equal(stream.getState().snapshot, null);
});

test('bad cursors fail visibly without resetting to a newest page or dropping retained evidence', async () => {
  let reads = 0; const paths = [];
  const { stream, timers } = reader(async (path) => {
    paths.push(path);
    if (reads++) throw Object.assign(new Error('invalid cursor'), { status: 400 });
    return envelope([event('old')], { next_cursor: 'old', has_more: false });
  });
  stream.subscribe(() => {}); await settle(); await timers.tick(2500);
  assert.equal(stream.getState().snapshot.items[0].id, 'old');
  assert.equal(timers.delays().length, 0);
  stream.refresh(); await settle();
  assert.match(paths.at(-1), /cursor=old/); stream.dispose();
});

test('revocation discards data and never falls back to another route', async () => {
  let reads = 0;
  const { stream, timers } = reader(async () => {
    if (reads++) throw Object.assign(new Error('forbidden'), { status: 403 });
    return envelope([event('private')]);
  });
  stream.subscribe(() => {}); await settle(); await timers.tick(2500);
  assert.equal(stream.getState().snapshot, null);
  assert.equal(timers.delays().length, 0); stream.dispose();
});

test('revocation clears a paused display even while another subscriber continues polling', async () => {
  let reads = 0; let pausedView;
  const { stream, timers } = reader(async () => {
    if (reads++) throw Object.assign(new Error('forbidden'), { status: 403 });
    return envelope([event('private')]);
  });
  const paused = stream.subscribe((state) => { pausedView = state; });
  stream.subscribe(() => {}); await settle();
  paused.setActive(false); await timers.tick(2500);
  assert.equal(pausedView.snapshot, null);
  assert.equal(pausedView.error.status, 403); stream.dispose();
});

test('more than eight scan pages retain every opaque cursor across bounded polling cycles', async () => {
  const paths = []; let page = 0;
  const { stream, timers } = reader(async (path) => {
    paths.push(path);
    if (!path.includes('/activity')) return { id: 'r1', status: 'completed', steps: [] };
    if (page > 0) assert.match(path, new RegExp(`after=opaque_${page}`));
    page += 1;
    return { scan_id: 'r1', status: 'completed', items: [event(`e${page}`, page)], pagination: { next_cursor: `opaque_${page}`, has_more: page < 10 } };
  }, 'scan');
  stream.subscribe(() => {}); await settle();
  assert.equal(page, 8);
  assert.equal(stream.getState().snapshot.items.length, 8);
  await timers.tick(2500);
  assert.equal(page, 10);
  assert.equal(stream.getState().snapshot.items.length, 10);
  assert.equal(paths.filter((path) => path.includes('/activity')).length, 10); stream.dispose();
});

test('explicit failure envelopes and mismatched exact executions cannot retain protected evidence', () => {
  const ref = { entry: 'check_result', target_id: 't1', check_id: 'c1', test_run_id: 'r1' };
  const payload = { subject: { target_id: 't1', check_id: 'c1' }, answer: { outcome: 'blocked', observed_behavior: 'private' }, primary: { test_run_id: 'r1', evidence_ids: ['private_ref'] }, request_summary: { method: 'GET' } };
  for (const state of ['denied', 'auth', 'not_found', 'expired', 'unbound']) {
    const model = normalizeEvidenceContext({ ...payload, state }, ref);
    assert.equal(model.state, state); assert.equal(model.answer, null); assert.equal(model.primary, null); assert.deepEqual(model.request.fields, []);
  }
  for (const mismatch of [{ subject: { target_id: 'other' } }, { subject: { check_id: 'other' } }, { primary: { test_run_id: 'other', evidence_ids: ['private_ref'] } }]) {
    const model = normalizeEvidenceContext({ ...payload, ...mismatch }, ref);
    assert.equal(model.state, 'not_found'); assert.equal(model.primary, null);
  }
});

test('Stop requested keeps following after database cancellation, without claiming worker stop', async () => {
  let reads = 0;
  const { stream, timers } = reader(async () => envelope([], { status: 'cancelled', stop: { state: reads++ ? 'acknowledged' : 'requested' } }));
  stream.subscribe(() => {}); await settle();
  assert.equal(activityIsLive(stream.getState().snapshot), true);
  assert.match(stopStateLabel(stream.getState().snapshot.stop), /acknowledgment pending/);
  await timers.tick(2500);
  assert.equal(activityIsLive(stream.getState().snapshot), false);
  assert.equal(stopStateLabel(stream.getState().snapshot.stop), 'Worker acknowledged Stop');
  assert.match(stopStateLabel({ state: 'unreachable' }), /not confirmed/);
  assert.match(stopStateLabel({ state: 'deadline_elapsed' }), /not confirmed/); stream.dispose();
});

test('capture omissions, paging and successful reads are distinct from completeness', () => {
  assert.match(captureWarnings(envelope([]))[0], /unknown/);
  const warnings = captureWarnings(envelope([], { has_more: true, capture: { status: 'incomplete', dropped_count: 2, delivery_failures: 3, sequence_gaps: [{ from: 7, to: 8 }] } }));
  for (const pattern of [/incomplete/, /2 activity/, /3 activity/, /7–8/, /More recorded pages/]) assert.ok(warnings.some((warning) => pattern.test(warning)));
  assert.deepEqual(captureWarnings(envelope([], { capture: { status: 'complete' } })), []);
});

test('assessment reader uses exact passive record and shared paged activity', async () => {
  const paths = [];
  const { stream } = reader(async (path) => { paths.push(path); return path.includes('/activity') ? { scan_id: 'r1', status: 'completed', items: [], has_more: false } : { id: 'r1', status: 'completed', steps: [] }; }, 'scan');
  stream.subscribe(() => {}); await settle();
  assert.deepEqual(paths, ['/v1/validation-scans/r1?advance=false', '/v1/validation-scans/r1/activity?limit=256']); stream.dispose();
});

test('Play retains the returned ID before any capped list reload and Stop confirmation freezes the scope', () => {
  const target = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
  assert.match(target, /const created = asDataItem\(accepted\.run\) \?\? accepted/);
  assert.match(target, /const runId = getString\(created, \['id'\], ''\)/);
  assert.match(target, /const record = targetRuns\.find\(\(run\) => run\.id === scopedAcceptedRun\.id\) \?\? scopedAcceptedRun\.record/);
  assert.match(target, /test_run_id: runId/);
  assert.match(target, /scan_id: acceptedScanId/);
  assert.ok(target.indexOf('test_run_id: runId') < target.indexOf('void loadTargetActivity();', target.indexOf('test_run_id: runId')));
  const workspace = readFileSync(new URL('../../apps/web/react/src/components/evidence/execution-inspector.tsx', import.meta.url), 'utf8');
  assert.match(workspace, /const id = confirm\?\.id/);
  assert.match(workspace, /setConfirm\(\{ kind: 'run', id: childId, scopeKey \}\)/);
  assert.match(workspace, /confirm.scopeKey !== scopeKey/);
  assert.match(workspace, /pinned_run_id: id \}, scan, scanActivity.error/);
  assert.doesNotMatch(workspace, /\[follow, setFollow\]|\[pinnedChild, setPinnedChild\]/);
  assert.match(workspace, /stopAllowed = canStartRun\(session.role\)/);
});


test('same-principal credential changes isolate shared reader scopes without exposing credentials', () => {
  const keyFor = createActivityReaderKey();
  const scope = { identity: 'tenant/user/role', authMode: 'jwt', id: 'r1', kind: 'run' };
  const original = { mode: 'jwt', access_token: 'secret-old-token', expires_at: 10 };
  const originalKey = keyFor({ ...scope, session: original });
  assert.equal(keyFor({ ...scope, session: { ...original } }), originalKey, 'unrelated hydration shares its exact credential epoch');
  for (const next of [{ ...original, access_token: 'secret-new-token' }, { ...original, expires_at: 20 }, { ...original, mode: 'dev-headers' }]) {
    const key = keyFor({ ...scope, session: next });
    assert.notEqual(key, originalKey);
    assert.doesNotMatch(key, /secret-old-token|secret-new-token|access_token|expires_at/);
  }
  const hook = readFileSync(new URL('../../apps/web/react/src/components/evidence/use-recorded-activity.ts', import.meta.url), 'utf8');
  assert.match(hook, /activityReaderKey\(\{ identity: scope, authMode: config.authMode, session, kind, id \}\)/);
  assert.match(hook, /committed.key === key \? committed.state : EMPTY_ACTIVITY_STATE/);
  assert.match(hook, /connected.unsubscribe\(\)/);
});

test('credential rotation clears a paused retained view and reconnects only with the new reader', async () => {
  const keyFor = createActivityReaderKey();
  const scope = { identity: 'same-principal', authMode: 'jwt', kind: 'run', id: 'r1' };
  const oldKey = keyFor({ ...scope, session: { access_token: 'old' } });
  const { stream: oldReader } = reader(async () => envelope([event('old-auth-event')]));
  let retained;
  const oldSubscription = oldReader.subscribe((state) => { retained = { key: oldKey, state }; });
  await settle(); oldSubscription.setActive(false);
  assert.equal(retained.state.snapshot.items[0].id, 'old-auth-event');
  const newKey = keyFor({ ...scope, session: { access_token: 'new' } });
  const visible = retained.key === newKey ? retained.state : { snapshot: null };
  assert.equal(visible.snapshot, null, 'paused never permits a prior credential scope');
  oldSubscription.unsubscribe(); oldReader.dispose();
  let newReads = 0;
  const { stream: newReader } = reader(async () => { newReads += 1; return envelope([event('new-auth-event')]); });
  const newSubscription = newReader.subscribe(() => {}, false);
  assert.equal(newReader.getState().snapshot, null);
  await settle(); assert.equal(newReads, 0, 'credential rebinding respects display Pause');
  newSubscription.setActive(true); await settle();
  assert.deepEqual(newReader.getState().snapshot.items.map((item) => item.id), ['new-auth-event']);
  newReader.dispose();
});

test('all dedicated reviewed starts propagate exact accepted execution identities to the shared Inspector', () => {
  const target = readFileSync(new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url), 'utf8');
  assert.equal((target.match(/onStarted=\{onReviewedExecutionStarted\}/g) ?? []).length, 3);
  assert.match(target, /scopeRef\.current !== executionScope/);
  assert.match(target, /targetId === entityId\) setAcceptedRun/);
  assert.match(target, /target_id: targetId, check_id: checkId, test_run_id: runId/);
  const origin = readFileSync(new URL('../../apps/web/react/src/components/targets/origin-relations.tsx', import.meta.url), 'utf8');
  assert.match(origin, /const run = rec\(accepted\.run\) \?\? accepted/);
  assert.match(origin, /\{ runId, checkId, targetId, record: run \}/);
  assert.match(origin, /accepted without a recorded run ID/);
  assert.match(origin, /run\.target_id !== targetId/);
  const firewall = readFileSync(new URL('../../apps/web/react/src/components/targets/entry-paths/firewall-change.tsx', import.meta.url), 'utf8');
  assert.match(firewall, /const runId = await startReviewedRetest/);
  assert.match(firewall, /checkId: review\.ref\.check_id, targetId: review\.ref\.target_id/);
  assert.match(firewall, /accepted without a recorded run ID/);
  const api = readFileSync(new URL('../../apps/web/react/src/lib/protection-validation-api.ts', import.meta.url), 'utf8');
  assert.match(api, /run\.target_id !== body\.target_id/);
  assert.match(api, /run\.check_id !== body\.check_id/);
});

test('comparison child Inspect controls use accepted IDs plus submitted-plan bindings, never current path metadata', () => {
  const path = readFileSync(new URL('../../apps/web/react/src/components/targets/entry-paths/path-comparison.tsx', import.meta.url), 'utf8');
  assert.match(path, /for \(const item of started\.items\)/);
  assert.match(path, /review\.plan\.items\.find\(\(candidate\) => candidate\.entry_path_id === item\.entry_path_id && candidate\.eligible\)/);
  assert.match(path, /runId: item\.test_run_id, checkId: planned\.check_id, targetId: planned\.target_id/);
  assert.match(path, /acceptedExecutions\?\.scope === startScope/);
  assert.match(path, /target_id: execution\.targetId, check_id: execution\.checkId, test_run_id: execution\.runId/);
  assert.match(path, /accepted without a recorded comparison ID/);
  assert.match(path, /no child execution ID was returned yet/);
  const workspace = readFileSync(new URL('../../apps/web/react/src/components/targets/entry-paths/entry-paths-workspace.tsx', import.meta.url), 'utf8');
  assert.match(workspace, /onStarted\(text, execution\)/);
});

test('dedicated accepted-start responses cannot commit after navigation, revocation or credential changes', () => {
  for (const name of ['origin-relations.tsx', 'entry-paths/firewall-change.tsx', 'entry-paths/path-comparison.tsx']) {
    const source = readFileSync(new URL(`../../apps/web/react/src/components/targets/${name}`, import.meta.url), 'utf8');
    assert.match(source, /sessionIdentity\(session\), config\.authMode, session\.mode, session\.access_token, session\.expires_at/);
    assert.match(source, /startScopeRef\.current === submittedScope && startGeneration\.current === submittedGeneration/);
    assert.match(source, /return \(\) => \{ startGeneration\.current \+= 1; startScopeRef\.current = '';/);
    assert.match(source, /if \(!current\(\)\) return;/);
  }
});

test('activity values keep dotted identifiers verbatim and humanise only plain snake_case codes', () => {
  assert.deepEqual(activityValueLabel('l7.waf_marker_rule.safe'), { text: 'l7.waf_marker_rule.safe', code: true });
  assert.deepEqual(activityValueLabel('waf.fingerprint.safe'), { text: 'waf.fingerprint.safe', code: true });
  const plain = activityValueLabel('outside_request_budget');
  assert.equal(plain.code, false);
  assert.doesNotMatch(plain.text, /_/);
  assert.match(plain.text, /request budget/i);
  assert.deepEqual(activityValueLabel(''), { text: '', code: false });
  assert.deepEqual(activityValueLabel(null), { text: '', code: false });
  const source = readFileSync(new URL('../../apps/web/react/src/components/targets/probe-activity.tsx', import.meta.url), 'utf8');
  assert.match(source, /label\.code \? <span className="mono">\{label\.text\}<\/span>/);
  assert.doesNotMatch(source, /String\(value\)\.replaceAll\('_', ' '\)/, 'dotted IDs are never half-humanised');
});

test('request counts state what was recorded and keep the authorized limit separate', () => {
  assert.equal(activityRequestsSentLabel(3), '3 requests sent (recorded)');
  assert.equal(activityRequestsSentLabel(0), '0 requests sent (recorded)');
  for (const missing of [null, undefined, '', 'n/a']) assert.equal(activityRequestsSentLabel(missing), 'Requests sent: not recorded');
  assert.equal(activityRequestLimitLabel(16), 'Limit: up to 16 requests');
  assert.equal(activityRequestLimitLabel(null), '');
  const source = readFileSync(new URL('../../apps/web/react/src/components/targets/probe-activity.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /attested operations|Planned probe maximum/);
  assert.doesNotMatch(source, /of \$\{?maxRequests\}? sent/, 'sent and limit are never merged into "0 of n sent"');
});

test('a received probe result is never presented as a verdict while correlation is pending', () => {
  const source = readFileSync(new URL('../../apps/web/react/src/components/targets/probe-activity.tsx', import.meta.url), 'utf8');
  assert.match(source, /result_received: 'Probe result received'/);
  assert.doesNotMatch(source, /'Result recorded'/);
  assert.match(source, /item\.stage === 'result_received' && running \? <><span>Probe response: /);
  assert.match(source, /<small>Not a verdict · correlating<\/small>/);
  const row = { runId: 'run_1', checkId: 'waf.fingerprint.safe', name: 'WAF check', status: 'running', requestsSent: 1, maxRequests: 4 };
  const logs = generateCheckProbeLogs(row, 'owned.test', [{ id: 'evt_result', test_run_id: 'run_1', check_id: row.checkId, producer_kind: 'signed_probe', signal_type: 'probe_result', timestamp: '2026-10-08T10:00:00.000Z', metadata: { external_result: 'blocked', status_code: 403 } }]);
  assert.equal(logs.length, 1);
  assert.match(logs[0].message, /\(probe observation, not a verdict\)$/);
});
