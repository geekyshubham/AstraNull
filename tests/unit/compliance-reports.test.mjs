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

  it('EVIDENCE-01: report export scrubs agent/placement vocabulary and agent ids from a seeded verdict', async () => {
    const { getStore } = await import('../../src/store.mjs');
    const store = getStore();
    // Seed a pre-ADR-0008 run + verdict carrying agent/placement wording and an agent id, as
    // historical/seeded prod data would.
    store.testRuns.push({
      id: 'run_legacy_agent', tenant_id: CTX.tenantId, target_group_id: 'tg_x', target_id: 'tgt_x',
      check_id: 'origin.direct_bypass.safe', status: 'verdicted', created_at: new Date().toISOString(),
    });
    store.verdicts.push({
      id: 'vd_legacy_agent', tenant_id: CTX.tenantId, test_run_id: 'run_legacy_agent', target_id: 'tgt_x',
      check_id: 'origin.direct_bypass.safe', verdict: 'penetrated', confidence: 'high',
      explanation: 'External response indicated block/timeout but the agent observed traffic — possible penetration with silent drop downstream.',
      placement_confidence: {
        level: 'Medium', status: 'observed_this_run',
        reason: 'Bound online agent reported unknown observation; path evidence is broader than host-level.',
        agent_id: 'agt_e563ad3b5baa04fd', observation_mode: 'unknown', evidence_event_id: 'evt_x',
      },
      evidence_ids: ['evt_x'], severity: 'medium', created_at: new Date().toISOString(),
    });

    const report = createReport(CTX, { kind: 'technical', title: 'legacy agent verdict export' });
    const jsonOut = exportReport(CTX, report.id, 'json');
    const serialized = JSON.stringify(jsonOut.payload);
    // No agent identifier reaches the customer-facing export anywhere.
    assert.doesNotMatch(serialized, /agt_e563ad3b5baa04fd/, 'agent_id must not be exported');
    assert.doesNotMatch(serialized, /observation_mode/, 'observation_mode key must be dropped');
    // The exported verdict record carries no agent/placement vocabulary.
    const exported = jsonOut.payload.verdicts.find((v) => v.test_run_id === 'run_legacy_agent');
    assert.doesNotMatch(exported.explanation, /\bagent\b/i, 'no "agent" wording in explanation');
    assert.doesNotMatch(exported.explanation, /placement/i, 'no "placement" wording in explanation');
    assert.doesNotMatch(exported.placement_confidence.reason, /\bagent\b/i, 'no "agent" wording in placement reason');
    assert.doesNotMatch(exported.placement_confidence.reason, /placement/i, 'no "placement" wording in placement reason');
    // The external-probe rewrite preserves the observation substance (no fabricated evidence).
    assert.equal(exported.verdict, 'penetrated', 'verdict unchanged');
    assert.equal(exported.confidence, 'high', 'confidence unchanged');
    assert.match(exported.explanation, /external probe recorded traffic reaching the declared path/);
    assert.equal('agent_id' in exported.placement_confidence, false);
    assert.equal(exported.placement_confidence.level, 'Medium', 'non-prose placement fields preserved');
    assert.equal(exported.placement_confidence.evidence_event_id, 'evt_x', 'evidence linkage preserved');
    // Custody manifest still verifies over the scrubbed payload.
    assert.equal(verifyCustodyManifest({ payload: jsonOut.payload, custody: jsonOut.custody }).ok, true);
    assertNoSecrets(serialized);
  });
});