import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CHECK_CATALOG, checkRequiresAdditionalInput, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { checkExclusionReason, checkSupportsTarget } from '../../apps/web/react/src/lib/check-picker.mjs';
import { buildRiskPlan, buildRiskPlanPrompt, normalizeRiskPlanRequest, parseRiskStory, parseValidationPlan } from '../../src/services/assistantRiskPlan.mjs';
import { createAssistantStore } from '../../src/services/assistant.mjs';
import { loadAssistantConfig } from '../../src/lib/assistantConfig.mjs';
import { ASSISTANT_RISK_PLAN_ROUTES } from '../../src/routes/assistantRiskPlanRoutes.mjs';

const ctx = { tenantId: 'ten_risk_fixture', userId: 'usr_fixture', role: 'admin' };
const now = Date.parse('2026-10-19T12:00:00Z');
const target = { id: 'tgt_risk', tenant_id: ctx.tenantId, kind: 'fqdn', value: 'https://user:secret@example.test/private?token=DO_NOT_LEAK' };
const runnable = CHECK_CATALOG.filter((check) => isCustomerRunnable(check, ctx) && !checkExclusionReason(check) && checkSupportsTarget(check, target) && !checkRequiresAdditionalInput(check, { target, env: {} }));
const first = runnable[0];
const second = runnable[1];
const finding = { id: 'fnd_risk', tenant_id: ctx.tenantId, target_id: target.id, check_id: first.check_id, status: 'open', severity: 'high', created_at: '2026-01-01T00:00:00Z', evidence_ids: ['ev_one'], title: 'Cookie: PRIVATE_COOKIE', raw_http: 'Authorization: Bearer PRIVATE_HTTP', system_summary: 'password=PRIVATE_SUMMARY' };
const readers = (overrides = {}) => ({
  getTarget: async () => target,
  listFindings: async () => ({ items: [finding], total: 1, has_more: false }),
  getFinding: async (_ctx, id) => id === finding.id ? finding : null,
  listTargetChecks: async () => runnable.map((check) => ({ ...check, requires_additional_input: false, additional_input_reason: null })),
  ...overrides,
});
const request = { target_id: target.id };
const optionsFor = (computed) => ({ context: { target_id: computed.target_id, snapshot_id: computed.snapshot_id }, validation: { target_id: computed.target_id, snapshot_id: computed.snapshot_id, source_finding_ids: computed.source_finding_ids, candidate_check_ids: computed.candidates?.map((row) => row.check_id) } });
const annotation = (computed, body) => JSON.stringify({ snapshot_id: computed.snapshot_id, target_id: computed.target_id, ...body });

test('route permissions deny before reading any source data', async () => {
  const cfg = { assistant: loadAssistantConfig({ ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: ctx.tenantId }) };
  for (const route of ASSISTANT_RISK_PLAN_ROUTES) {
    for (const scopes of [[], ['finding:read'], ['finding:read', 'check:read'], ...(route.path.endsWith('validation-plan') ? [['finding:read', 'target_group:read']] : [])]) {
      const response = { setHeader() {}, writeHead(status) { this.status = status; }, end(body) { this.body = JSON.parse(body); } };
      await route.handle({}, response, { ...ctx, scopes, persistenceMode: 'postgres', auditService: { appendAuditEvent: async () => {} } }, cfg, { tools: new Proxy({}, { get() { assert.fail('No data reader before permission gate'); } }) });
      assert.equal(response.status, 403);
      assert.equal(response.body.error, 'forbidden');
    }
  }
});

test('request accepts only bounded target and exact unique source IDs, never execution options', () => {
  assert.deepEqual(normalizeRiskPlanRequest(request, 'validation_plan'), request);
  assert.deepEqual(normalizeRiskPlanRequest({ ...request, finding_ids: ['fnd_risk'] }, 'risk_story'), { ...request, finding_ids: ['fnd_risk'] });
  for (const body of [null, [], { target_id: 'bad id' }, { ...request, run: true }, { ...request, finding_ids: [] }, { ...request, finding_ids: ['f', 'f'] }, { ...request, finding_ids: Array.from({ length: 21 }, (_, n) => `f${n}`) }]) assert.equal(normalizeRiskPlanRequest(body, 'risk_story'), null);
  assert.equal(normalizeRiskPlanRequest({ ...request, finding_ids: ['f'] }, 'validation_plan'), null);
});

test('stories keep metadata facts and conditional hypotheses separate, with stale and unknown evidence labels', async () => {
  const { computed } = await buildRiskPlan(ctx, request, 'risk_story', readers({ listFindings: async () => ({ items: [finding, { ...finding, id: 'fnd_unknown', created_at: undefined, evidence_ids: [] }], total: 2 }) }), { now });
  assert.deepEqual(computed.scope, { target_ids: [target.id], includes_subdomains: false, confidence: 'external_only' });
  assert.deepEqual(computed.source_finding_ids, ['fnd_risk', 'fnd_unknown']);
  assert.deepEqual(computed.stories[0].source_finding_ids, ['fnd_risk']);
  assert.match(computed.stories[0].hypothesis, /^If /);
  assert.ok(computed.observed_facts[0].data_labels.includes('stale'));
  assert.ok(computed.observed_facts[1].data_labels.includes('unknown_age'));
  assert.ok(computed.observed_facts[1].data_labels.includes('evidence_unknown'));
  assert.equal(computed.observed_facts[0].status, finding.status);
  assert.equal(computed.score, undefined);
  assert.equal(computed.verdict, undefined);
});

test('snapshots and prompts never include raw HTTP, target URL, finding description or secrets', async () => {
  const { computed } = await buildRiskPlan(ctx, request, 'risk_story', readers(), { now });
  const text = JSON.stringify(computed) + buildRiskPlanPrompt(computed, 'risk_story');
  for (const secret of ['PRIVATE_COOKIE', 'PRIVATE_HTTP', 'PRIVATE_SUMMARY', 'DO_NOT_LEAK', 'example.test', 'raw_http']) assert.ok(!text.includes(secret), secret);
  assert.match(text, /UNTRUSTED_DATA_BEGIN/);
  assert.match(text, /fnd_risk/);
});

test('exact finding selections fail closed for foreign target, foreign tenant, mismatched and unavailable IDs', async () => {
  for (const row of [null, { ...finding, id: 'fnd_other' }, { ...finding, target_id: 'tgt_other' }, { ...finding, tenant_id: 'ten_foreign' }]) {
    const built = await buildRiskPlan(ctx, { ...request, finding_ids: [finding.id] }, 'risk_story', readers({ getFinding: async () => row }));
    assert.equal(built.status, 404);
  }
  const scoped = await buildRiskPlan(ctx, { ...request, finding_ids: [finding.id] }, 'risk_story', readers());
  assert.deepEqual(scoped.computed.source_finding_ids, [finding.id]);
});

test('default findings reject unrelated scope and label truncated or unknown completeness', async () => {
  for (const envelope of [{ items: [finding], total: 21 }, { items: [finding], has_more: true }, { items: [finding] }]) {
    const built = await buildRiskPlan(ctx, request, 'risk_story', readers({ listFindings: async () => envelope }));
    assert.equal(built.computed.incomplete, true);
  }
  const filtered = await buildRiskPlan(ctx, request, 'risk_story', readers({ listFindings: async () => ({ items: [finding, { ...finding, id: 'fnd_foreign', target_id: 'other' }], total: 2 }) }));
  assert.deepEqual(filtered.computed.source_finding_ids, [finding.id]);
  assert.equal(filtered.computed.incomplete, true);
});

test('empty source set is unknown evidence, never a pass, and unavailable readers fail closed', async () => {
  const empty = await buildRiskPlan(ctx, request, 'risk_story', readers({ listFindings: async () => ({ items: [], total: 0 }) }));
  assert.deepEqual(empty.computed.stories, []);
  for (const overrides of [{ getTarget: undefined }, { listFindings: undefined }, { listFindings: async () => ({ error: 'offline' }) }, { listTargetChecks: undefined }]) {
    assert.equal((await buildRiskPlan(ctx, request, 'validation_plan', readers(overrides))).status, 503);
  }
  for (const row of [null, { ...target, tenant_id: 'other' }, { ...target, id: 'other' }, { ...target, archived_at: '2026-01-01' }]) assert.equal((await buildRiskPlan(ctx, request, 'risk_story', readers({ getTarget: async () => row }))).status, 404);
});

test('recommender uses canonical publication, customer runnability, target kind and target-scoped eligibility', async () => {
  const soc = CHECK_CATALOG.find((check) => !isCustomerRunnable(check, ctx));
  const incompatible = CHECK_CATALOG.find((check) => isCustomerRunnable(check, ctx) && !checkExclusionReason(check) && !checkSupportsTarget(check, target));
  assert.ok(soc && incompatible);
  const catalog = [
    { ...first, requires_additional_input: false },
    { ...second, requires_additional_input: true, additional_input_reason: 'declared_probe_path_required' },
    { ...runnable[2], requires_additional_input: undefined },
    { ...soc, requires_additional_input: false },
    { ...incompatible, requires_additional_input: false },
    { ...first, check_id: 'invented.safe', requires_additional_input: false },
  ];
  const { computed } = await buildRiskPlan(ctx, request, 'validation_plan', readers({ listTargetChecks: async () => catalog }));
  assert.deepEqual(computed.check_ids, [first.check_id]);
  assert.deepEqual(computed.excluded.map((row) => row.reason), ['declared_probe_path_required', 'target_eligibility_unknown', 'soc_gated_check', 'target_kind_not_supported', 'not_published']);
  assert.equal(computed.requires_review, true);
  assert.match(computed.admission, /server admission/);
});

test('computed order links exact loaded finding checks first, is bounded and stable, never redefines groups', async () => {
  const a = await buildRiskPlan(ctx, request, 'validation_plan', readers(), { now });
  const b = await buildRiskPlan(ctx, request, 'validation_plan', readers(), { now });
  assert.equal(a.computed.check_ids[0], first.check_id);
  assert.ok(a.computed.check_ids.length <= 12);
  assert.deepEqual(a.computed.check_ids, b.computed.check_ids);
  assert.deepEqual(a.computed.candidates[0].source_finding_ids, [finding.id]);
  assert.match(a.computed.selection_basis, /Not a complete assessment/);
  assert.equal(a.computed.groups, undefined);
});

test('partial catalog never produces a recommendation', async () => {
  for (const listed of [{ items: [], has_more: true }, { items: [], next_cursor: 'next' }, { items: [], total: 1 }, Array.from({ length: 501 }, () => first)]) {
    assert.equal((await buildRiskPlan(ctx, request, 'validation_plan', readers({ listTargetChecks: async () => listed }))).error, 'risk_plan_catalog_incomplete');
  }
});

test('risk parser binds exact source IDs and both snapshot and target from private job validation', async () => {
  const { computed } = await buildRiskPlan(ctx, request, 'risk_story', readers());
  const body = { stories: [{ source_finding_ids: [finding.id], hypothesis: 'If still present, this may matter.' }] };
  assert.equal(parseRiskStory(annotation(computed, body), optionsFor(computed)).ai, true);
  for (const bad of [
    { ...body, target_id: 'other' }, { ...body, snapshot_id: 'other' },
    { stories: [{ source_finding_ids: ['foreign'], hypothesis: 'x' }] },
    { stories: [{ source_finding_ids: [finding.id, finding.id], hypothesis: 'x' }] },
    { stories: [{ source_finding_ids: [finding.id], hypothesis: 'x', observed_facts: ['invented'] }] },
    { ...body, score: 100 }, { stories: [] },
  ]) assert.equal(parseRiskStory(annotation(computed, bad), optionsFor(computed)), null);
  assert.equal(parseRiskStory(annotation(computed, body), {}), null);
  assert.equal(parseRiskStory('not JSON', optionsFor(computed)), null);
  assert.equal(parseRiskStory(annotation(computed, body), { ...optionsFor(computed), context: { target_id: 'other' } }), null);
});

test('plan parser validates every proposed ID and order against candidates; no extra execution fields', async () => {
  const { computed } = await buildRiskPlan(ctx, request, 'validation_plan', readers());
  const chosen = computed.check_ids.slice(0, 2).reverse();
  const body = { check_ids: chosen, rationale: 'Prioritize these eligible checks for review.' };
  assert.deepEqual(parseValidationPlan(annotation(computed, body), optionsFor(computed)).check_ids, chosen);
  for (const patch of [{ check_ids: ['invented'] }, { check_ids: [first.check_id, first.check_id] }, { check_ids: [] }, { check_ids: computed.candidates.slice(0, 13).map((row) => row.check_id) }, { target_id: 'other' }, { schedule: 'now' }, { rationale: 'x'.repeat(1201) }]) assert.equal(parseValidationPlan(annotation(computed, { ...body, ...patch }), optionsFor(computed)), null);
});

test('structured fake-model lifecycle returns owned annotations only, no tools or execution', async () => {
  const { computed } = await buildRiskPlan(ctx, request, 'validation_plan', readers());
  const cfg = { assistant: loadAssistantConfig({ ASTRANULL_ASSISTANT_ENABLED: '1', ASTRANULL_ASSISTANT_TENANTS: ctx.tenantId, ASTRANULL_ASSISTANT_RUNNER_TOKEN: 'test-risk-plan-token-for-fixtures-1234567890' }) };
  const store = createAssistantStore();
  store.markRunnerSeen();
  const validation = optionsFor(computed).validation;
  const created = await store.createStructuredJob(ctx, { purpose: 'validation_plan', prompt: buildRiskPlanPrompt(computed, 'validation_plan'), context: optionsFor(computed).context, validation, requiredPermissions: ['target_group:read', 'finding:read', 'check:read'] }, cfg);
  assert.ok(created.job_id);
  validation.candidate_check_ids.push('invented'); // The job must own a private clone.
  const lease = store.leaseJob(cfg);
  assert.equal(lease.tools, false);
  assert.deepEqual(lease.allowed_tools, []);
  assert.equal(lease.validation, undefined);
  assert.equal(store.getJob({ ...ctx, userId: 'other' }, created.job_id, cfg), null);
  assert.equal(store.getJob({ ...ctx, tenantId: 'other' }, created.job_id, cfg), null);
  store.completeJob(created.job_id, { status: 'done', content: annotation(computed, { check_ids: [first.check_id], rationale: 'Review the recorded finding.' }) }, cfg);
  assert.deepEqual(store.getJob(ctx, created.job_id, cfg).response.validation_plan.check_ids, [first.check_id]);
  assert.equal(store.getJob({ ...ctx, scopes: ['finding:read'] }, created.job_id, cfg), null);
  const secondJob = await store.createStructuredJob(ctx, { purpose: 'validation_plan', prompt: 'fixture', context: optionsFor(computed).context, validation: optionsFor(computed).validation }, cfg);
  store.leaseJob(cfg);
  store.completeJob(secondJob.job_id, { status: 'done', content: annotation(computed, { check_ids: ['invented'], rationale: 'No.' }) }, cfg);
  assert.equal(store.getJob(ctx, secondJob.job_id, cfg).status, 'failed');
});
