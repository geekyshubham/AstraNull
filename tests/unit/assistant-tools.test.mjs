import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createAssistantStore, sanitizePageContext, validateDataMarkers } from '../../src/services/assistant.mjs';
import { executeAssistantTool, isAssistantToolName, MAX_TOOL_CALLS } from '../../src/services/assistantTools.mjs';
import { loadAssistantConfig } from '../../src/lib/assistantConfig.mjs';

const TOKEN = 'r'.repeat(40);
const cfg = { assistant: loadAssistantConfig({ ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: 'ten_a,ten_b', ASTRANULL_ASSISTANT_RUNNER_TOKEN: TOKEN }) };
const denials = [];
const quietAudit = { appendAuditEvent: async (entry) => denials.push(entry) };
const ctxFor = (tenantId, role = 'admin') => ({ tenantId, userId: `usr_${role}`, role, persistenceMode: 'postgres', auditService: quietAudit });

const DATA = {
  ten_a: {
    findings: [
      { id: 'fnd_a1', tenant_id: 'ten_a', title: 'No rate limiting', severity: 'high', status: 'open', check_id: 'l7.rate', target_id: 'tgt_a1' },
      { id: 'fnd_a2', tenant_id: 'ten_a', title: 'Origin exposed', severity: 'high', status: 'open', check_id: 'edge.origin', target_id: 'tgt_a1' },
      { id: 'fnd_a3', tenant_id: 'ten_a', title: 'Weak TLS', severity: 'low', status: 'resolved', check_id: 'tls.weak', target_id: 'tgt_a2', system_summary: 'Authorization: Bearer leaked-secret-value' },
    ],
    targets: [{ id: 'tgt_a1', tenant_id: 'ten_a', value: 'shop.example.test', kind: 'fqdn' }, { id: 'tgt_a2', tenant_id: 'ten_a', value: 'api.example.test', kind: 'fqdn' }],
  },
  ten_b: {
    findings: [{ id: 'fnd_b1', tenant_id: 'ten_b', title: 'Other tenant secret finding', severity: 'critical', status: 'open', check_id: 'l7.rate', target_id: 'tgt_b1' }],
    targets: [{ id: 'tgt_b1', tenant_id: 'ten_b', value: 'other.example.test', kind: 'fqdn' }],
  },
};

const tools = {
  listTargets: async (ctx) => ({ items: DATA[ctx.tenantId]?.targets ?? [] }),
  getTarget: async (ctx, id) => (DATA[ctx.tenantId]?.targets ?? []).find((row) => row.id === id) ?? null,
  listFindings: async (ctx) => ({ items: DATA[ctx.tenantId]?.findings ?? [] }),
  getFinding: async (ctx, id) => (DATA[ctx.tenantId]?.findings ?? []).find((row) => row.id === id) ?? null,
  listRuns: async () => ({ items: [] }),
  getRun: async () => null,
  listChecks: async () => ({ items: [] }),
  getCheck: async () => null,
  getState: async () => ({}),
  getEdgeCoverage: async () => ({}),
  listSchedules: async () => ({ items: [] }),
  listAuditEvents: async () => ({ items: [{ id: 'aud_1', action: 'target.created' }] }),
};
const counter = () => {
  let n = 0;
  return () => `Q${(n += 1)}`;
};
const body = (result) => JSON.parse(result.result_text.split('\n').slice(1, -1).join('\n'));

describe('page context sanitisation', () => {
  it('keeps bounded, clean fields only', () => {
    const page = sanitizePageContext({
      route: '/findings/fnd_1?tab=evidence<script>',
      title: `Finding \u0007detail ${'x'.repeat(200)}`,
      kind: 'finding-detail!',
      tab: 'evidence',
      entity: { type: 'finding', id: 'fnd_1' },
      filters: Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`f${i}`, 'v'])),
      facts: { severity: 'high', nested: { no: 'objects' }, long: 'y'.repeat(500) },
      extra: 'dropped',
    });
    assert.ok(page.route.length <= 60);
    assert.ok(!page.route.includes('<'));
    assert.ok(page.title.length <= 120);
    assert.ok(!page.title.includes('\u0007'));
    assert.equal(page.kind, 'finding-detail');
    assert.deepEqual(page.entity, { type: 'finding', id: 'fnd_1' });
    assert.equal(Object.keys(page.filters).length, 12);
    assert.equal(page.facts.severity, 'high');
    assert.ok(!('nested' in page.facts));
    assert.ok(page.facts.long.length <= 200);
    assert.ok(!('extra' in page));
  });

  it('drops unknown entity types and malformed ids', () => {
    assert.equal(sanitizePageContext({ entity: { type: 'tenant', id: 'ten_b' } }), null);
    assert.equal(sanitizePageContext({ entity: { type: 'finding', id: '../../etc' } }), null);
    assert.deepEqual(sanitizePageContext('targets'), { route: 'targets' });
    assert.equal(sanitizePageContext(['x']), null);
  });
});

describe('assistant data tools', () => {
  it('only sees the caller tenant', async () => {
    const own = body(await executeAssistantTool(ctxFor('ten_a'), 'list_findings', {}, tools));
    assert.deepEqual(own.items.map((row) => row.id).sort(), ['fnd_a1', 'fnd_a2', 'fnd_a3']);
    const foreign = await executeAssistantTool(ctxFor('ten_a'), 'get_finding', { finding_id: 'fnd_b1' }, tools);
    assert.equal(foreign.ok, false);
    assert.ok(!foreign.result_text.includes('Other tenant'));
  });

  it('redacts and fences every result', async () => {
    const result = await executeAssistantTool(ctxFor('ten_a'), 'get_finding', { finding_id: 'fnd_a3' }, tools);
    assert.match(result.result_text, /^<<<UNTRUSTED_DATA_BEGIN tool result get_finding>>>/);
    assert.ok(!result.result_text.includes('leaked-secret-value'));
  });

  it('denies tools the role lacks', async () => {
    const viewer = await executeAssistantTool(ctxFor('ten_a', 'viewer'), 'list_audit_events', {}, tools);
    assert.equal(viewer.ok, false);
    assert.deepEqual(body(viewer), { error: 'permission_denied', permission: 'audit:read' });
    assert.ok(denials.some((entry) => entry.action === 'rbac.denied' && entry.metadata.tool === 'list_audit_events'));
    const auditor = await executeAssistantTool(ctxFor('ten_a', 'auditor'), 'list_audit_events', {}, tools);
    assert.equal(auditor.ok, true);
  });

  it('rejects unknown tools and malformed args', async () => {
    assert.equal(isAssistantToolName('drop_tables'), false);
    assert.deepEqual(await executeAssistantTool(ctxFor('ten_a'), 'drop_tables', {}, tools), { error: 'unknown_tool', status: 400 });
    assert.equal((await executeAssistantTool(ctxFor('ten_a'), 'list_findings', ['x'], tools)).status, 400);
    assert.equal((await executeAssistantTool(ctxFor('ten_a'), 'query_data', { dataset: 'users' }, tools)).status, 400);
  });

  it('aggregates allow-listed fields and registers the table', async () => {
    const result = await executeAssistantTool(ctxFor('ten_a'), 'query_data', { dataset: 'findings', group_by: 'severity', filters: { status: 'open' } }, tools, { nextDataId: counter() });
    assert.equal(result.ok, true);
    assert.equal(result.data_result.id, 'Q1');
    assert.deepEqual(result.data_result.columns.map((column) => column.key), ['severity', 'count']);
    assert.deepEqual(result.data_result.rows, [['high', 2]]);
    assert.equal(result.data_result.suggested_visual, 'donut');
    assert.equal(body(result).data_result_id, 'Q1');
    for (const args of [{ dataset: 'findings', group_by: 'tenant_id' }, { dataset: 'findings', filters: { tenant_id: 'ten_b' } }]) {
      const rejected = await executeAssistantTool(ctxFor('ten_a'), 'query_data', args, tools, { nextDataId: counter() });
      assert.equal(rejected.ok, false);
      assert.equal(rejected.data_result, null);
      assert.equal(body(rejected).error, 'invalid_args');
    }
  });

  it('returns row tables when not grouped', async () => {
    const result = await executeAssistantTool(ctxFor('ten_a'), 'query_data', { dataset: 'targets', limit: 1 }, tools, { nextDataId: counter() });
    assert.equal(result.data_result.suggested_visual, 'table');
    assert.equal(result.data_result.rows.length, 1);
  });
});

describe('data markers', () => {
  const results = [{ id: 'Q1' }, { id: 'Q2' }];
  it('keeps registered markers and strips the rest', () => {
    const content = validateDataMarkers('See [[data:Q1|bar]] and [[data:Q9]] or [[data:Q2|pie]].', results);
    assert.match(content, /\[\[data:Q1\|bar\]\]/);
    assert.ok(!content.includes('Q9'));
    assert.match(content, /\[\[data:Q2\]\]/);
    assert.ok(!content.includes('pie'));
  });
});

describe('job tool calls', () => {
  const ask = { messages: [{ role: 'user', content: 'How many open findings by severity?' }] };
  const setup = async (role = 'admin') => {
    const store = createAssistantStore();
    const audits = [];
    const deps = { tools, recordAudit: async (entry) => audits.push(entry) };
    store.markRunnerSeen();
    const created = await store.createJob(ctxFor('ten_a', role), ask, cfg, deps);
    return { store, deps, audits, id: created.job_id };
  };

  it('needs a running job, a known tool and stays under the cap', async () => {
    const { store, deps, audits, id } = await setup();
    assert.equal((await store.runJobTool(id, { name: 'list_findings' }, cfg, deps)).error, 'job_not_running');
    const lease = store.leaseJob(cfg);
    assert.equal(lease.max_tool_calls, MAX_TOOL_CALLS);
    assert.equal(lease.tools, true);
    assert.match(lease.prompt, /astranull-tool/);
    assert.equal((await store.runJobTool(id, { name: 'shell' }, cfg, deps)).error, 'unknown_tool');
    assert.equal((await store.runJobTool('asj_missing', { name: 'list_findings' }, cfg, deps)).status, 404);
    const first = await store.runJobTool(id, { name: 'query_data', args: { dataset: 'findings', group_by: 'severity' } }, cfg, deps);
    assert.equal(first.data_result_id, 'Q1');
    assert.equal(first.tool_calls_remaining, MAX_TOOL_CALLS - 1);
    assert.deepEqual(audits.at(-1).metadata, { job_id: id, tool: 'query_data' });
    for (let i = 1; i < MAX_TOOL_CALLS; i += 1) await store.runJobTool(id, { name: 'list_targets' }, cfg, deps);
    assert.equal((await store.runJobTool(id, { name: 'list_targets' }, cfg, deps)).status, 429);
  });

  it('returns only referenced data results and drops the captured context', async () => {
    const { store, deps, id } = await setup();
    store.leaseJob(cfg);
    await store.runJobTool(id, { name: 'query_data', args: { dataset: 'findings', group_by: 'severity' } }, cfg, deps);
    await store.runJobTool(id, { name: 'query_data', args: { dataset: 'targets', group_by: 'kind' } }, cfg, deps);
    store.completeJob(id, { status: 'done', content: 'Two high findings.\n\n[[data:Q1|bar]]\n[[data:Q7]]', tool_calls: [{ name: 'query_data', summary: 'query_data (dataset=findings)' }, { name: '', summary: 'x' }] }, cfg);
    const job = store.getJob(ctxFor('ten_a'), id, cfg);
    assert.deepEqual(job.response.data_results.map((result) => result.id), ['Q1']);
    assert.ok(!job.response.content.includes('Q7'));
    assert.deepEqual(job.response.tool_calls, [{ name: 'query_data', summary: 'query_data (dataset=findings)' }]);
    assert.ok(!('ctx' in store._jobs.get(id)));
    assert.equal((await store.runJobTool(id, { name: 'list_targets' }, cfg, deps)).error, 'job_not_running');
  });

  it('runs tools with the asker role, not the runner', async () => {
    const { store, deps, id } = await setup('viewer');
    store.leaseJob(cfg);
    const denied = await store.runJobTool(id, { name: 'list_audit_events' }, cfg, deps);
    assert.equal(denied.ok, false);
    assert.match(denied.result_text, /permission_denied/);
  });
});

describe('assistant query_data reads legacy finding lifecycle', () => {
  it('counts a finding whose lifecycle is stored in state', async () => {
    const { executeAssistantTool } = await import('../../src/services/assistantTools.mjs');
    const findings = [
      { id: 'f1', tenant_id: 't1', severity: 's2', state: 'open' },
      { id: 'f2', tenant_id: 't1', severity: 's2', status: 'open' },
      { id: 'f3', tenant_id: 't1', severity: 's3', status: 'open' },
      { id: 'f4', tenant_id: 't1', severity: 's2', status: 'resolved' },
    ];
    const deps = { listFindings: async () => ({ items: findings, total: findings.length }) };
    const ctx = { tenantId: 't1', userId: 'u1', role: 'owner' };
    const result = await executeAssistantTool(ctx, 'query_data', { dataset: 'findings', group_by: 'severity', filters: { status: 'open' } }, deps, { nextDataId: () => 'Q1' });
    assert.deepEqual(result.data_result.rows, [['s2', 2], ['s3', 1]]);
  });
});
