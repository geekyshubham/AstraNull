import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { getStore, resetStoreForTests, clearStoreCacheForTests, resolveDataFile } from '../../src/store.mjs';
import { verifyAuditChain } from '../../src/audit.mjs';
import { createAssistantStore } from '../../src/services/assistant.mjs';
import { createDevAssistantWidgetRepository, normalizeWidgetConfig, buildWidgetData,
  listVisibleWidgets, parseWidgetCommentary, widgetCommentaryRequest } from '../../src/services/assistantWidgets.mjs';

const ctx = { tenantId: 'ten_widget', userId: 'usr_widget', role: 'viewer' };
const config = { name: 'Read-only findings', question: 'What was observed?', template: 'summary' };
const AT = '2026-10-19T00:00:00.000Z';
const row = (i, extra = {}) => ({ id: `fnd_${i}`, tenant_id: ctx.tenantId, target_id: 'tgt_widget', title: `Observed ${i}`, severity: 'S2', status: 'open', raw_http: 'RAW_SECRET_EVIDENCE', ...extra });
const envelope = (items, extra = {}) => ({ items, total: items.length, has_more: false, page: 1, ...extra });
const tools = { listFindings: async () => envelope([row(1)]), listTargets: async () => envelope([{ id: 'tgt_widget', tenant_id: ctx.tenantId }]) };
const throwsCode = (fn, code) => assert.throws(fn, (error) => error.code === code);
beforeEach(() => { resetStoreForTests(); });

test('strict bounded configuration rejects executable/unknown fields, aliases and non-string values', () => {
  assert.deepEqual(normalizeWidgetConfig(config), config);
  assert.deepEqual(normalizeWidgetConfig({ ...config, target_id: 'tgt_widget', severity: 'high', template: 'finding_list' }), { ...config, target_id: 'tgt_widget', severity: 'high', template: 'finding_list' });
  for (const patch of [{ name: 'x'.repeat(81) }, { question: 'x'.repeat(501) }, { name: '' }, { question: 'not\nplain' },
    { template: 'custom_html' }, { html: '<script>bad</script>' }, { sql: 'select *' }, { renderer: 'run' }, { severity: 'S2' },
    { severity: null }, { target_id: '../foreign' }, { target_id: 1 }, { name: {} }, { question: null }]) {
    assert.equal(normalizeWidgetConfig({ ...config, ...patch }), null, JSON.stringify(patch));
  }
  assert.match(normalizeWidgetConfig({ ...config, question: 'token=secret-value' }).question, /REDACTED/);
});

test('dev definitions survive disk reload, are copied, own-user/tenant isolated and audit atomically with no model results', () => {
  const oldNoPersist = process.env.ASTRANULL_NO_PERSIST, oldMode = process.env.ASTRANULL_PERSISTENCE_MODE;
  delete process.env.ASTRANULL_NO_PERSIST; delete process.env.ASTRANULL_PERSISTENCE_MODE;
  try {
    const repo = createDevAssistantWidgetRepository({ now: () => new Date(AT) });
    const widget = repo.create(ctx, config);
    assert.equal(widget.version, 1); assert.equal(widget.created_at, AT);
    widget.config.name = 'Do not mutate storage';
    assert.equal(repo.list(ctx)[0].config.name, config.name);
    for (const foreign of [{ ...ctx, tenantId: 'ten_foreign' }, { ...ctx, userId: 'usr_foreign' }]) {
      assert.deepEqual(repo.list(foreign), []);
      throwsCode(() => repo.update(foreign, widget.id, config, 1), 'widget_not_found');
      throwsCode(() => repo.remove(foreign, widget.id, 1), 'widget_not_found');
    }
    const updated = repo.update(ctx, widget.id, { ...config, name: 'Edited' }, 1);
    assert.equal(updated.version, 2);
    throwsCode(() => repo.update(ctx, widget.id, config, 1), 'widget_version_conflict');
    throwsCode(() => repo.remove(ctx, widget.id, 1), 'widget_version_conflict');
    clearStoreCacheForTests();
    assert.deepEqual(repo.list(ctx), [updated]);
    const saved = JSON.parse(readFileSync(resolveDataFile(), 'utf8'));
    assert.deepEqual(Object.keys(saved.assistantWidgets[0]).sort(), ['config', 'created_at', 'id', 'tenant_id', 'updated_at', 'user_id', 'version']);
    assert.equal(saved.auditLog.length, 2); assert.equal(JSON.stringify(saved.auditLog).includes(config.question), false);
    assert.equal(verifyAuditChain(saved.auditLog).valid, true);
    assert.deepEqual(repo.remove(ctx, widget.id, 2), { deleted: true });
    assert.equal(getStore().auditLog.at(-1).action, 'assistant.widget_deleted');
  } finally {
    if (oldNoPersist === undefined) delete process.env.ASTRANULL_NO_PERSIST; else process.env.ASTRANULL_NO_PERSIST = oldNoPersist;
    if (oldMode === undefined) delete process.env.ASTRANULL_PERSISTENCE_MODE; else process.env.ASTRANULL_PERSISTENCE_MODE = oldMode;
  }
});

test('dev quota12, expected versions, failed persistence, RBAC and postgres fallback all fail closed', () => {
  const repo = createDevAssistantWidgetRepository();
  for (let i = 0; i < 12; i++) repo.create(ctx, config);
  throwsCode(() => repo.create(ctx, config), 'widget_limit_reached');
  assert.equal(getStore().assistantWidgets.length, 12);
  const widget = repo.list(ctx)[0], before = JSON.stringify(getStore());
  const failing = createDevAssistantWidgetRepository({ commit: () => { throw new Error('disk failed'); } });
  assert.throws(() => failing.update(ctx, widget.id, config, 1), /disk failed/);
  assert.throws(() => failing.remove(ctx, widget.id, 1), /disk failed/);
  assert.equal(JSON.stringify(getStore()), before);
  for (const version of [undefined, '1', 0, -1, 1.5, Number.MAX_SAFE_INTEGER]) throwsCode(() => repo.remove(ctx, widget.id, version), 'invalid_expected_version');
  throwsCode(() => repo.list({ ...ctx, persistenceMode: 'postgres' }), 'assistant_widgets_unavailable');
  for (const actor of [{ ...ctx, userId: '' }, { ...ctx, role: 'unknown' }, { ...ctx, scopes: ['target_group:read'] }, { ...ctx, serviceAccountId: 'svc_widget' }]) {
    throwsCode(() => repo.list(actor), 'forbidden');
  }
});

test('computed widget enforces exact target/severity bounds, canonical severity, no raw evidence, max6 rows and no extrapolated totals', async () => {
  const requests = [];
  const scoped = { ...config, target_id: 'tgt_widget', severity: 'high' };
  const data = await buildWidgetData(ctx, scoped, { ...tools, listFindings: async (_ctx, query) => {
    requests.push(query); return envelope(Array.from({ length: 9 }, (_, i) => row(i)));
  } }, { now: () => new Date(AT) });
  assert.equal(data.count, 9); assert.equal(data.count_is_total, true); assert.equal(data.scope.complete, true);
  assert.equal(data.rows.length, 6); assert.deepEqual(data.citations, data.rows.map((item) => item.id));
  assert.equal(data.rows[0].severity, 'high'); assert.equal(data.observed_at, AT);
  assert.equal(JSON.stringify(data).includes('RAW_SECRET'), false);
  assert.deepEqual(requests, [{ limit: 200, page: 1, target_id: 'tgt_widget', severity: 'high' }]);
  const oversized = await buildWidgetData(ctx, config, { listFindings: async () => envelope(Array.from({ length: 205 }, (_, i) => row(i)), { total: 900, has_more: true }) });
  assert.equal(oversized.count, 200); assert.equal(oversized.count_is_total, false); assert.equal(oversized.scope.findings_complete, false);
  const loose = await buildWidgetData(ctx, scoped, { ...tools, listFindings: async () => envelope([row(1), row(2, { severity: 'low' }), row(3, { tenant_id: 'ten_foreign' }), row(4, { target_id: 'tgt_foreign' }), row(1), {}]) });
  assert.equal(loose.count, 1); assert.equal(loose.count_is_total, false);
  const unknown = await buildWidgetData(ctx, config, { listFindings: async () => [row(1)] });
  assert.equal(unknown.count, 1); assert.equal(unknown.count_is_total, false);
});

test('scope absence, unavailable datasets, missing records and permissions never broaden to tenant data', async () => {
  const scoped = { ...config, target_id: 'tgt_widget' };
  await assert.rejects(buildWidgetData({ ...ctx, scopes: ['finding:read'] }, scoped, tools), (error) => error.code === 'forbidden');
  await assert.rejects(buildWidgetData(ctx, { ...scoped, target_id: 'tgt_foreign' }, tools), (error) => error.code === 'target_not_found');
  await assert.rejects(buildWidgetData(ctx, config, {}), (error) => error.code === 'widget_data_unavailable');
  await assert.rejects(buildWidgetData(ctx, config, { listFindings: async () => { throw new Error('private sql failure'); } }), (error) => error.code === 'widget_data_unavailable');
  const empty = await buildWidgetData(ctx, config, { listFindings: async () => envelope([]) });
  assert.equal(empty.count, 0); assert.equal(empty.count_is_total, true); assert.deepEqual(empty.rows, []);
  const repo = createDevAssistantWidgetRepository();
  repo.create(ctx, config); repo.create(ctx, scoped);
  assert.equal((await listVisibleWidgets({ ...ctx, scopes: ['finding:read'] }, repo, tools)).length, 1);
  assert.equal((await listVisibleWidgets(ctx, repo, { listTargets: async () => envelope([]) })).length, 1);
});

test('commentary uses private exact finding IDs, strict plain text and model cannot supply metrics or renderers', async () => {
  const data = await buildWidgetData(ctx, config, tools), request = widgetCommentaryRequest(config, data);
  const valid = { text: 'One observed finding requires review.', citations: ['fnd_1'] };
  assert.deepEqual(parseWidgetCommentary(JSON.stringify(valid), { validation: request.validation }), valid);
  assert.equal(parseWidgetCommentary(JSON.stringify(valid)), null);
  for (const bad of [{ ...valid, citations: ['fnd_foreign'] }, { ...valid, citations: [] }, { ...valid, count: 900 },
    { ...valid, text: '<script>bad()</script>' }, { ...valid, text: '[[data:Q1]]' }, { ...valid, text: 'x'.repeat(1001) }, { ...valid, citations: ['fnd_1', 'fnd_1'] }]) {
    assert.equal(parseWidgetCommentary(JSON.stringify(bad), { validation: request.validation }), null);
  }
  assert.match(request.prompt, /UNTRUSTED_DATA_BEGIN/); assert.equal(request.prompt.includes('RAW_SECRET_EVIDENCE'), false);
  assert.deepEqual(request.validation.finding_ids, ['fnd_1']); assert.deepEqual(request.requiredPermissions, ['finding:read']);
  const jobs = createAssistantStore({ now: () => Date.parse(AT) });
  const runtime = { assistant: { enabled: true, tenants: [ctx.tenantId], runnerToken: 'local_fake_token' } };
  jobs.markRunnerSeen();
  const queued = await jobs.createStructuredJob(ctx, request, runtime);
  request.validation.citations.push('fnd_foreign');
  const lease = jobs.leaseJob(runtime); assert.equal(lease.tools, false); assert.deepEqual(lease.allowed_tools, []);
  jobs.completeJob(queued.job_id, { status: 'done', content: JSON.stringify({ ...valid, citations: ['fnd_foreign'] }) }, runtime);
  assert.equal(jobs.getJob(ctx, queued.job_id, runtime).error, 'widget_commentary_unparseable');
});
