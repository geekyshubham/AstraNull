import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  FINDING_LIST_Q_COLUMNS,
  findingListGroupSql,
  findingListQSql,
  parseFindingListQuery,
} from '../../src/lib/findingList.mjs';
import { containsAgentPlacementVocabulary } from '../../src/lib/outsideInEvidence.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import {
  createPostgresValidationServices,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  VALIDATION_PROBE_JOB_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/validationServiceAdapters.mjs';
import { listFindings, listFindingsEnvelope } from '../../src/services/findings.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function seed() {
  freshStore();
  const store = getStore();
  store.targets.push(
    { id: 'tgt_moved', tenant_id: 'ten_demo', target_group_id: 'tg_1', deleted_at: null },
    { id: 'tgt_dead', tenant_id: 'ten_demo', target_group_id: 'tg_1', deleted_at: '2026-01-01T00:00:00.000Z' },
    { id: 'tgt_foreign', tenant_id: 'ten_other', target_group_id: 'tg_1', deleted_at: null },
  );
  store.findings.push(
    finding('f3', 'tg_page', 'tgt_page', 'open', 'medium', 'chk_page', '2026-08-03T00:00:00.000Z', 'Page three'),
    finding('f2', 'tg_page', 'tgt_page', 'open', 'medium', 'chk_page', '2026-08-02T00:00:00.000Z', 'Page two'),
    finding('f1', 'tg_page', 'tgt_page', 'open', 'medium', 'chk_page', '2026-08-01T00:00:00.000Z', 'Page one'),
    finding('f_open', 'tg_1', 'tgt_1', 'open', 'high', 'chk_open', '2026-07-02T00:00:00.000Z', 'Edge gap'),
    finding('f_closed', 'tg_1', 'tgt_1', 'closed', 'low', 'chk_closed', '2026-07-01T00:00:00.000Z', 'Old gap'),
    finding('f_member', 'tg_other', 'tgt_moved', 'open', 'medium', 'chk_member', '2026-07-03T00:00:00.000Z', 'Moved member'),
    finding('f_dead', 'tg_stale', 'tgt_dead', 'open', 'medium', 'chk_dead', '2026-07-04T00:00:00.000Z', 'Dead member'),
    finding('f_other', 'tg_1', 'tgt_foreign', 'open', 'high', 'chk_open', '2026-07-05T00:00:00.000Z', 'Foreign', 'ten_other'),
    finding('f_secret', 'tg_1', 'tgt_1', 'open', 'medium', 'chk_secret', '2026-07-06T00:00:00.000Z', 'Visible title', 'ten_demo', 'super-secret-note agent placement'),
  );
}

function finding(id, group, target, status, severity, check, created, title, tenant = 'ten_demo', notes = null) {
  return {
    id,
    tenant_id: tenant,
    target_group_id: group,
    target_id: target,
    test_run_id: `run_${id}`,
    check_id: check,
    status,
    severity,
    title,
    notes,
    created_at: created,
  };
}

function stubFrom(methodNames, impls = {}) {
  const stub = {};
  for (const name of methodNames) stub[name] = impls[name] ?? (async () => null);
  return { ...stub, ...impls };
}

describe('current-release findings pagination', () => {
  it('pages the full query and keeps status, group, and search predicates', () => {
    seed();
    const page = listFindingsEnvelope(CTX, { target_group_id: 'tg_page', limit: 2 });
    assert.equal(page.total, 3);
    assert.equal(page.count, 3);
    assert.equal(page.page, 1);
    assert.equal(page.pages, 2);
    assert.equal(page.has_more, true);
    assert.deepEqual(page.items.map((item) => item.id), ['f3', 'f2']);
    assert.equal(page.meta.empty_reason, null);

    const second = listFindingsEnvelope(CTX, { target_group_id: 'tg_page', limit: 2, page: 2 });
    assert.equal(second.total, 3);
    assert.equal(second.count, 3);
    assert.notEqual(second.count, second.items.length);
    assert.equal(second.has_more, false);
    assert.deepEqual(second.items.map((item) => item.id), ['f1']);
    assert.equal(second.meta.empty_reason, null);

    const grouped = listFindingsEnvelope(CTX, { target_group_id: 'tg_1', limit: 50 });
    assert.deepEqual(grouped.items.map((item) => item.id).sort(), ['f_closed', 'f_member', 'f_open', 'f_secret']);
    const openGroup = listFindingsEnvelope(CTX, { target_group_id: 'tg_1', status: 'open', limit: 50 });
    assert.deepEqual(openGroup.items.map((item) => item.id).sort(), ['f_member', 'f_open', 'f_secret']);
    const allStatus = listFindingsEnvelope(CTX, { target_group_id: 'tg_1', status: 'all', limit: 50 });
    assert.equal(allStatus.total, grouped.total);
    const closed = listFindingsEnvelope(CTX, { target_group_id: 'tg_1', status: 'closed', limit: 50 });
    assert.deepEqual(closed.items.map((item) => item.id), ['f_closed']);

    const secret = listFindingsEnvelope(CTX, { q: 'super-secret-note', limit: 50 });
    assert.equal(secret.total, 0);
    assert.equal(secret.meta.empty_reason, 'No findings match this search.');
    const visible = listFindingsEnvelope(CTX, { q: 'Visible', limit: 50 });
    assert.deepEqual(visible.items.map((item) => item.id), ['f_secret']);
    assert.equal(containsAgentPlacementVocabulary(visible.items[0].notes), false);

    const missing = listFindingsEnvelope(CTX, { check_id: 'chk_missing' });
    assert.equal(missing.total, 0);
    assert.equal(missing.items.length, 0);
    assert.equal(missing.pages, 0);
    assert.equal(missing.has_more, false);
    assert.equal(missing.meta.empty_reason, 'No findings match this check filter.');

    const unbounded = listFindings(CTX);
    const envelope = listFindingsEnvelope(CTX);
    assert.equal(envelope.limit, 50);
    assert.equal(envelope.total, unbounded.length);
    assert.equal(envelope.count, unbounded.length);
    assert.equal(listFindings({ tenantId: 'ten_other' }).some((item) => item.id === 'f_open'), false);

    const bad = listFindingsEnvelope(CTX, { status: 'nope' });
    assert.equal(bad.status, 400);
    assert.equal(bad.error, 'invalid_query_value');
    assert.equal(bad.field, 'status');
    assert.throws(() => listFindings(CTX, { limit: 0 }), /out of range/);
    assert.equal(listFindingsEnvelope(CTX, { notes: 'secret' }).error, 'unknown_query_param');
    assert.equal(listFindingsEnvelope(CTX, { q: 'x'.repeat(201) }).status, 400);
    assert.equal(listFindingsEnvelope(CTX, { page: 2, offset: 0, limit: 2 }).error, 'invalid_query_value');
  });

  it('keeps the search and group SQL off notes and deleted targets', () => {
    assert.equal(FINDING_LIST_Q_COLUMNS.includes('notes'), false);
    assert.equal(FINDING_LIST_Q_COLUMNS.includes('remediation_template'), false);
    assert.equal(findingListQSql('$3').includes('notes'), false);
    assert.equal(findingListGroupSql('$2').includes('member.deleted_at IS NULL'), true);
    assert.equal(findingListGroupSql('$2').includes('member.tenant_id = f.tenant_id'), true);
    const query = parseFindingListQuery({ status: 'all', severity: 'S2', limit: '2', page: '2' }, { paginate: true });
    assert.equal(query.status, null);
    assert.equal(query.severity, 'S2');
    assert.equal(query.severity_class, 'high');
    assert.equal(parseFindingListQuery({ severity: 'moderate' }).severity_class, 'medium');
    assert.equal(parseFindingListQuery({ q: 'x', severity: 'weird-token' }).severity_class, 'unknown');
    assert.equal(parseFindingListQuery({ severity: 'all' }).severity_class, null);
    assert.equal(query.limit, 2);
    assert.equal(query.offset, 2);
  });

  it('matches canonical severity aliases, unknown rows, and effective legacy status', () => {
    seed();
    const store = getStore();
    const push = (parts) => {
      store.findings.push(finding(
        parts.id, 'tg_1', 'tgt_1', parts.status, parts.severity,
        `chk_${parts.id}`, '2026-07-08T00:00:00.000Z', parts.title ?? parts.id,
        'ten_demo', null,
      ));
      const row = store.findings[store.findings.length - 1];
      if (parts.state !== undefined) { delete row.status; row.state = parts.state; }
      if (parts.clearLifecycle) { delete row.status; delete row.state; }
    };
    push({ id: 'f_s1', severity: 'S1' });
    push({ id: 'f_s2', severity: 's2' });
    push({ id: 'f_s3', severity: 'S3' });
    push({ id: 'f_s4', severity: 's4' });
    push({ id: 'f_moderate', severity: 'moderate' });
    push({ id: 'f_case', severity: 'HIGH ' });
    push({ id: 'f_weird', severity: 'weird-class' });
    push({ id: 'f_state_open', state: 'open', severity: 'high' });
    push({ id: 'f_state_closed', state: 'closed', severity: 'high' });
    push({ id: 'f_no_lifecycle', clearLifecycle: true, severity: 'high' });

    // The alias class matches every equivalent recorded class both ways.
    assert.deepEqual(
      listFindingsEnvelope(CTX, { severity: 'high', limit: 50 }).items.map((item) => item.id).sort(),
      ['f_case', 'f_no_lifecycle', 'f_open', 'f_s2', 'f_state_closed', 'f_state_open'].sort(),
    );
    const critical = listFindingsEnvelope(CTX, { severity: 'S1', limit: 50 });
    assert.deepEqual(critical.items.map((item) => item.id), ['f_s1']);
    assert.equal(critical.total, 1);
    const moderate = listFindingsEnvelope(CTX, { severity: 'moderate', limit: 50 });
    // The moderate alias covers the S3 rows and every medium-seeded row.
    assert.deepEqual(
      moderate.items.map((item) => item.id).sort(),
      ['f1', 'f2', 'f3', 'f_dead', 'f_member', 'f_moderate', 'f_s3', 'f_secret'].sort(),
    );
    // A non-recognized recorded value is the unknown class, not low.
    const unknown = listFindingsEnvelope(CTX, { severity: 'unknown', limit: 50 });
    assert.deepEqual(unknown.items.map((item) => item.id), ['f_weird']);
    assert.equal(unknown.total, 1);
    // The recorded value and detail are preserved on projection.
    assert.deepEqual(listFindings(CTX, { severity: 'unknown' }).map((item) => item.severity), ['weird-class']);

    // Legacy state-only rows and missing lifecycle behave as the portal
    // findingStatus fallback: open unless a closure stands.
    const openState = listFindingsEnvelope(CTX, { status: 'open', limit: 100 });
    assert.equal(openState.items.some((item) => item.id === 'f_state_open'), true);
    assert.equal(openState.items.some((item) => item.id === 'f_no_lifecycle'), true);
    assert.equal(openState.items.some((item) => item.id === 'f_state_closed'), false);
    // Count and page stay in agreement for the same effective filter.
    const openPage = listFindingsEnvelope(CTX, { status: 'open', target_group_id: 'tg_1', limit: 2, page: 2 });
    assert.equal(openPage.total, listFindingsEnvelope(CTX, { status: 'open', target_group_id: 'tg_1', limit: 100 }).total);
    // Backwards compatibility: an exact closed lifecycle query excludes the
    // legacy state rows from the closed bucket only when its recorded value is
    // a closure; the state=closed row matches status=closed by class parity.
    const closedNow = listFindingsEnvelope(CTX, { status: 'closed', limit: 50 });
    assert.deepEqual(closedNow.items.map((item) => item.id).sort(), ['f_closed', 'f_state_closed'].sort());
  });

  it('envelope total comes from the page reader, not the loaded rows', async () => {
    let calls = 0;
    const validationEvidence = stubFrom(VALIDATION_EVIDENCE_REPOSITORY_METHODS, {
      async listFindingsPage() {
        calls += 1;
        return {
          items: [{ id: 'f_page', title: 'Visible', notes: 'agent placement remains stored' }],
          total: 4,
        };
      },
      async listFindings() {
        throw new Error('envelope must not load the array');
      },
    });
    const services = createPostgresValidationServices({
      validationEvidence,
      audit: stubFrom(VALIDATION_AUDIT_REPOSITORY_METHODS),
      coreCatalog: stubFrom(VALIDATION_CORE_CATALOG_REPOSITORY_METHODS),
      probeJobs: stubFrom(VALIDATION_PROBE_JOB_REPOSITORY_METHODS),
      killSwitch: stubFrom(VALIDATION_KILL_SWITCH_REPOSITORY_METHODS),
    });
    const body = await services.findings.listFindingsEnvelope(CTX, { limit: 1 });
    assert.equal(calls, 1);
    assert.equal(body.total, 4);
    assert.equal(body.count, 4);
    assert.equal(body.items.length, 1);
    assert.equal(containsAgentPlacementVocabulary(body.items[0].notes), false);
    const invalid = await services.findings.listFindingsEnvelope(CTX, { status: 'nope' });
    assert.equal(invalid.status, 400);
    assert.equal(calls, 1);
  });

  it('listFindingsPage reads count and page on one SQL statement snapshot', async () => {
    const queries = [];
    const client = {
      async query(text, params) {
        queries.push({ text, params });
        if (text.includes('LEFT JOIN page')) {
          return {
            rows: [
              {
                id: 'f3', tenant_id: CTX.tenantId, title: 'Page three',
                severity: 'medium', status: 'open', evidence_ids: [], created_at: '2026-08-03',
                total: 3,
              },
              { total: 3, id: null },
            ],
          };
        }
        if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(text.trim()) || text.includes('set_config')) {
          return { rows: [] };
        }
        throw new Error(`unexpected second statement: ${text}`);
      },
      release() {},
    };
    const repo = createValidationEvidenceRepository({ async connect() { return client; } });
    const page = await repo.listFindingsPage(CTX, { target_group_id: 'tg_page', limit: 2, page: 2 });
    const dataQueries = queries.filter((entry) => (
      entry.text.includes('FROM findings')
      || entry.text.includes('LEFT JOIN page')
    ));
    assert.equal(dataQueries.length, 1);
    const text = dataQueries[0].text;
    assert.equal(text.includes('f.tenant_id = $1'), true);
    assert.equal(text.includes('COUNT(*)::int AS total'), true);
    assert.equal(text.includes('LEFT JOIN page ON TRUE'), true);
    assert.equal(dataQueries[0].params[0], CTX.tenantId);
    assert.deepEqual(dataQueries[0].params.slice(1), ['tg_page', 2, 2]);
    assert.deepEqual(page.items.map((item) => item.id), ['f3']);
    assert.equal(page.total, 3);
  });

  it('listFindings and listFindingsPage keep the tenant predicate in the SQL text', async () => {
    const texts = [];
    const recording = {
      async query(text, params) { texts.push(text); return { rows: [] }; },
      release() {},
    };
    const pool = { async connect() { return recording; } };
    const strictRepo = createValidationEvidenceRepository(pool);
    await strictRepo.listFindings(CTX, { target_group_id: 'tg_page', limit: 2 });
    await strictRepo.listFindingsPage(CTX, { status: 'open', limit: 1 });
    await strictRepo.listFindingsPage(CTX, { severity: 'S2', limit: 1 });
    for (const text of texts) {
      if (text.includes('FROM findings')) {
        assert.match(text, /f\.tenant_id = \$1/);
        assert.doesNotMatch(text, /WHERE \$/);
      }
    }
    const listSql = texts.find((text) => text.includes('ORDER BY f.created_at DESC, f.id DESC') && text.startsWith('SELECT'));
    assert.match(listSql, /f\.target_group_id = \$2/);
    const pageSql = texts.find((text) => text.includes('LEFT JOIN page'));
    assert.match(pageSql, /lower\(btrim\(f\.status\)\) = \$2/);
    const severityPage = texts.find((text) => text.includes("WHEN 's2'"));
    assert.equal(severityPage != null, true);
    assert.doesNotMatch(severityPage, /f\.severity = \$/);
    assert.match(severityPage, /f\.tenant_id = \$1/);
  });
});
