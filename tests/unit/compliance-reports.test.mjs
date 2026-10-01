import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  REPORT_EXPORT_FORMATS,
  REPORT_KINDS,
  REPORT_PERIODS,
  buildComplianceMapping,
  getReportTemplate,
  listReportTemplates,
  normalizeReportKind,
  normalizeReportPeriod,
  reportCapabilities,
  reportPeriodLabel,
} from '../../src/contracts/complianceReports.mjs';
import { verifyCustodyManifest } from '../../src/lib/custody.mjs';
import { createReport, exportReport } from '../../src/services/reports.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_test', role: 'admin' };
const SECRET_MARKERS = [/ast_[A-Za-z0-9_-]{8,}/, /agc_[A-Za-z0-9_-]{8,}/];

function assertNoSecrets(text) {
  for (const pattern of SECRET_MARKERS) {
    assert.doesNotMatch(text, pattern);
  }
}

describe('compliance report contracts', () => {
  it('lists all report templates and normalizes kinds with unknown fallback', () => {
    const templates = listReportTemplates();
    assert.equal(templates.length, REPORT_KINDS.length);
    assert.deepEqual(
      templates.map((t) => t.kind).sort(),
      [...REPORT_KINDS].sort(),
    );
    assert.equal(normalizeReportKind('soc2'), 'soc2');
    assert.equal(normalizeReportKind('SOC-2'), 'soc2');
    assert.equal(normalizeReportKind('iso-27001'), 'iso27001');
    assert.equal(normalizeReportKind('not_a_real_kind'), 'technical');
    assert.equal(normalizeReportKind(undefined), 'technical');
  });

  it('reportCapabilities exposes every backend kind and export format with labels', () => {
    const capabilities = reportCapabilities();
    assert.deepEqual(
      capabilities.kinds.map((option) => option.value),
      [...REPORT_KINDS],
    );
    assert.deepEqual(
      capabilities.formats.map((option) => option.value),
      [...REPORT_EXPORT_FORMATS],
    );
    for (const option of [...capabilities.kinds, ...capabilities.formats]) {
      assert.equal(typeof option.label, 'string');
      assert.ok(option.label.length > 0, `missing label for ${option.value}`);
      // Labels are human-readable, not raw enum values.
      assert.doesNotMatch(option.label, /_/);
    }
    assert.equal(capabilities.default_kind, normalizeReportKind(undefined));
    assert.ok(REPORT_EXPORT_FORMATS.includes(capabilities.default_format));
  });

  it('exposes reporting periods with labels and normalizes unknown windows to null', () => {
    const capabilities = reportCapabilities();
    assert.deepEqual(
      capabilities.periods.map((option) => option.value),
      [...REPORT_PERIODS],
    );
    for (const option of capabilities.periods) {
      assert.equal(typeof option.label, 'string');
      assert.ok(option.label.length > 0, `missing label for ${option.value}`);
      assert.doesNotMatch(option.label, /[_-]/);
    }
    assert.equal(capabilities.default_period, null);
    assert.equal(normalizeReportPeriod('last-30-days'), 'last-30-days');
    assert.equal(normalizeReportPeriod('LAST_30_DAYS'), 'last-30-days');
    assert.equal(normalizeReportPeriod(undefined), null);
    assert.equal(normalizeReportPeriod(''), null);
    assert.equal(normalizeReportPeriod('last-decade'), null);
    assert.equal(normalizeReportPeriod({}), null);
    assert.equal(reportPeriodLabel('quarter'), 'Current quarter');
    assert.equal(reportPeriodLabel('nope'), null);
  });

  it('createReport stores the requested period and defaults to null', () => {
    freshStore();
    const withPeriod = createReport(CTX, { kind: 'technical', period: 'quarter' });
    assert.equal(withPeriod.period, 'quarter');
    assert.equal(withPeriod.summary.period, 'quarter');
    const withoutPeriod = createReport(CTX, { kind: 'technical' });
    assert.equal(withoutPeriod.period, null);
    assert.equal(withoutPeriod.summary.period, null);
  });

  it('buildComplianceMapping covers framework report kinds', () => {
    for (const kind of ['soc2', 'iso27001', 'dora', 'nis2', 'internal_audit']) {
      const mapping = buildComplianceMapping(kind);
      const template = getReportTemplate(kind);
      assert.equal(mapping.report_kind, template.kind);
      assert.ok(mapping.entries.length >= 3);
      assert.ok(mapping.entries.every((e) => e.framework && e.control_id && e.control_area));
      assert.ok(mapping.disclaimer.includes('does not certify'));
    }
  });
});

describe('report service compliance export', () => {
  beforeEach(() => {
    freshStore();
  });

  it('creates DORA report with compliance summary and exports mapping in all formats', () => {
    const report = createReport(CTX, { kind: 'dora', title: 'DORA mapping test' });
    assert.equal(report.kind, 'dora');
    assert.equal(report.summary.compliance.report_kind, 'dora');
    assert.ok(report.summary.compliance.control_mapping_count >= 3);
    assert.ok(report.summary.compliance.frameworks.includes('DORA'));

    const jsonOut = exportReport(CTX, report.id, 'json');
    assert.ok(jsonOut);
    assert.ok(jsonOut.payload.compliance_mapping);
    assert.equal(jsonOut.payload.compliance_mapping.report_kind, 'dora');
    assert.ok(jsonOut.payload.compliance_mapping.entries.some((e) => e.framework === 'DORA'));
    assert.equal(
      verifyCustodyManifest({ payload: jsonOut.payload, custody: jsonOut.custody }).ok,
      true,
    );
    assertNoSecrets(JSON.stringify(jsonOut));

    const mdOut = exportReport(CTX, report.id, 'markdown');
    assert.match(mdOut.content, /## Compliance mapping/);
    assert.match(mdOut.content, /DORA/);
    assert.match(mdOut.content, /## Custody/);
    assertNoSecrets(mdOut.content);

    const htmlOut = exportReport(CTX, report.id, 'html');
    assert.match(htmlOut.content, /<h2>Compliance mapping<\/h2>/);
    assert.match(htmlOut.content, /DORA/);
    assertNoSecrets(htmlOut.content);
  });

  it('SOC 2 export includes framework controls without raw payloads', () => {
    const report = createReport(CTX, { kind: 'soc2', title: 'SOC 2 pack' });
    const jsonOut = exportReport(CTX, report.id, 'json');
    const soc2Entries = jsonOut.payload.compliance_mapping.entries.filter((e) => e.framework === 'SOC 2');
    assert.ok(soc2Entries.length >= 4);
    assert.doesNotMatch(JSON.stringify(jsonOut.payload), /packet_payload|raw_packet/);
  });

  it('EVIDENCE-01: report export scrubs agent/placement vocabulary, agent ids, placement_confidence field, and legacy summary', async () => {
    const { getStore } = await import('../../src/store.mjs');
    const store = getStore();
    // Seed a pre-ADR-0008 run + verdict carrying agent/placement wording and an agent id, as
    // historical/seeded prod data would.
    store.testRuns.push({
      id: 'run_legacy_agent', tenant_id: CTX.tenantId, target_group_id: 'tg_x', target_id: 'tgt_x',
      check_id: 'origin.direct_bypass.safe', status: 'verdicted', created_at: new Date().toISOString(),
    });
    const storedVerdict = {
      id: 'vd_legacy_agent', tenant_id: CTX.tenantId, test_run_id: 'run_legacy_agent', target_id: 'tgt_x',
      check_id: 'origin.direct_bypass.safe', verdict: 'penetrated', confidence: 'high',
      explanation: 'External response indicated block/timeout but the agent observed traffic — possible penetration with silent drop downstream.',
      placement_confidence: {
        level: 'Medium', status: 'observed_this_run',
        reason: 'Bound online agent reported unknown observation; path evidence is broader than host-level.',
        agent_id: 'agt_e563ad3b5baa04fd', observation_mode: 'unknown', evidence_event_id: 'evt_x',
      },
      evidence_ids: ['evt_x'], severity: 'medium', created_at: new Date().toISOString(),
    };
    store.verdicts.push(storedVerdict);

    const report = createReport(CTX, { kind: 'technical', title: 'legacy verdict export regression' });
    // Inject a production-like legacy summary: the pre-ADR-0008 "Agent placement & health"
    // readiness factor plus a nested placement_diagnostics block carrying agent identifiers.
    const storedReport = store.reports.find((r) => r.id === report.id);
    storedReport.summary.readiness_factors = [
      { key: 'coverage', label: 'Validation coverage', score: 18 },
      { key: 'agent_placement', label: 'Agent placement & health', score: 15 },
      { key: 'evidence_freshness', label: 'Evidence freshness', score: 10 },
      { key: 'change_management', label: 'Change management discipline', score: 7 },
    ];
    storedReport.summary.placement_diagnostics = {
      proven: 1,
      missing_agent: 2,
      bound_agent_ids: ['agt_e563ad3b5baa04fd'],
      online_bound_agent_ids: ['agt_11112222'],
      unbound_online_agent_count: 1,
    };
    const storedSummarySnapshot = JSON.parse(JSON.stringify(storedReport.summary));

    const jsonOut = exportReport(CTX, report.id, 'json');
    const serialized = JSON.stringify(jsonOut.payload);
    // Zero customer-visible agent/placement vocabulary and zero agent ids anywhere in the export.
    assert.doesNotMatch(serialized, /\b(agent|agents|placement)\b/i, 'no agent/placement vocabulary in export');
    assert.doesNotMatch(serialized, /agt_/, 'no agent ids in export');
    assert.doesNotMatch(serialized, /observation_mode/, 'observation_mode key must be dropped');

    // Legacy summary content is stripped at export projection time.
    const factorLabels = (jsonOut.payload.summary.readiness_factors ?? []).map((f) => f.label);
    assert.ok(!factorLabels.includes('Agent placement & health'), 'legacy readiness factor must be dropped');
    // "management" is NOT over-stripped (token-safe matching).
    assert.ok(factorLabels.includes('Change management discipline'), 'management factor preserved');
    assert.ok(factorLabels.includes('Validation coverage'));
    assert.equal('placement_diagnostics' in jsonOut.payload.summary, false, 'placement_diagnostics dropped');

    // The exported verdict record carries no `placement_confidence` field and clean prose.
    const exported = jsonOut.payload.verdicts.find((v) => v.test_run_id === 'run_legacy_agent');
    assert.equal('placement_confidence' in exported, false, 'placement_confidence field must be gone');
    assert.doesNotMatch(exported.explanation, /\b(agent|agents|placement)\b/i, 'no agent/placement wording in explanation');
    // Verdict/confidence/evidence preserved; explanation rewritten (no fabricated evidence).
    assert.equal(exported.verdict, 'penetrated', 'verdict unchanged');
    assert.equal(exported.confidence, 'high', 'confidence unchanged');
    assert.deepEqual(exported.evidence_ids, ['evt_x'], 'evidence linkage preserved');
    assert.match(exported.explanation, /external probe recorded traffic reaching the declared path/);

    // Stored objects are untouched (internal/historical evidence preserved).
    assert.match(storedVerdict.explanation, /the agent observed traffic/);
    assert.equal(storedVerdict.placement_confidence.agent_id, 'agt_e563ad3b5baa04fd');
    assert.deepEqual(storedReport.summary, storedSummarySnapshot, 'stored summary unchanged by export');

    // Custody manifest still verifies over the scrubbed, delivered payload.
    assert.equal(verifyCustodyManifest({ payload: jsonOut.payload, custody: jsonOut.custody }).ok, true);
    assertNoSecrets(serialized);

    // Markdown/HTML remain working over the same scrubbed payload.
    const mdOut = exportReport(CTX, report.id, 'markdown');
    assert.match(mdOut.content, /## Verdicts/);
    assert.doesNotMatch(mdOut.content, /agt_/);
    const htmlOut = exportReport(CTX, report.id, 'html');
    assert.match(htmlOut.content, /<h2>Verdicts<\/h2>/);
    assert.doesNotMatch(htmlOut.content, /agt_/);
  });
});