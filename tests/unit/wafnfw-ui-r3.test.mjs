import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, checkAdditionalInputReason, checkRequiresAdditionalInput, getCheckById } from '../../src/contracts/checks.mjs';
import { buildVerdictReplay } from '../../src/lib/verdictReplay.mjs';
import { useIsolatedDevDataDir } from '../helpers/dev-data-dir.mjs';
import {
  ADDITIONAL_INPUT_REASON_COPY,
  DECLARATION_KEYS,
  additionalInputReasonCopy,
  checkPrerequisite,
  controlsHref,
  prerequisiteCta,
  prerequisiteSection,
  prerequisiteTone,
  targetRunnableIndex,
} from '../../apps/web/react/src/lib/control-declarations.mjs';
import { withTargetDependentChecks } from '../../apps/web/react/src/lib/check-picker.mjs';
import { customCanaryMembers, rowEvidenceState } from '../../apps/web/react/src/lib/domain-checks.mjs';
import { normalizeRuleCoverage } from '../../apps/web/react/src/lib/rule-coverage.mjs';
import { REGRADED_LABEL, regradeModel, verdictReplayModel } from '../../apps/web/react/src/lib/verdict-replay.mjs';
import { FIX_VERIFIED_BASIS_LABELS, FIX_VERIFIED_BASIS_UNKNOWN, fixVerifiedBasis } from '../../apps/web/react/src/lib/finding-lifecycle.mjs';
import { formatAuditAction } from '../../apps/web/react/src/lib/utils.ts';

const FQDN = { id: 'tgt_fqdn', kind: 'fqdn', value: 'shop.example.test' };
const EMPTY = { version: 1 };
const CONTROL_SECTIONS = new Set([...Object.values(DECLARATION_KEYS).map((meta) => meta.section), 'origin_relations']);

function serverItem(check, declarations, target = FQDN) {
  const context = { target, declarations, env: {} };
  const requires = checkRequiresAdditionalInput(check, context);
  return { ...check, requires_additional_input: requires, additional_input_reason: requires ? checkAdditionalInputReason(check, context) : null };
}

function serverReasonCodes() {
  const source = readFileSync(new URL('../../src/contracts/checks.mjs', import.meta.url), 'utf8');
  const start = source.indexOf('export function targetInputRefusal');
  const end = source.indexOf('export function customerSelectableChecks');
  const body = source.slice(start, end);
  const codes = new Set();
  for (const match of body.matchAll(/error: '([a-z0-9_]+)'/g)) codes.add(match[1]);
  for (const match of body.matchAll(/return '([a-z0-9_]+)'/g)) codes.add(match[1]);
  return [...codes];
}

describe('per-item refusal codes', () => {
  it('has plain copy for every reason the server can return', () => {
    const codes = serverReasonCodes();
    assert.ok(codes.length >= 11, codes.join(', '));
    for (const code of codes) {
      const copy = additionalInputReasonCopy(code);
      assert.ok(copy, `missing copy for ${code}`);
      assert.doesNotMatch(copy.label, /_/, code);
      assert.doesNotMatch(copy.detail, /\b[a-z]+_[a-z_]+\b/, code);
      if (copy.section) assert.ok(CONTROL_SECTIONS.has(copy.section), `${code} links to unknown section ${copy.section}`);
    }
  });

  it('uses the ticket wording for the declared requirements', () => {
    assert.equal(ADDITIONAL_INPUT_REASON_COPY.declared_udp_deny_required.label, 'Needs a declared UDP deny rule');
    assert.equal(ADDITIONAL_INPUT_REASON_COPY.declared_origin_lockdown_required.label, 'Needs origin lockdown declared');
    assert.equal(ADDITIONAL_INPUT_REASON_COPY.port_required.label, 'Needs a port');
    assert.equal(ADDITIONAL_INPUT_REASON_COPY.port_or_declared_deny_required.label, 'Needs a declared deny rule or a host:port target');
  });

  it('labels and deep-links each declared-requirement check from the server reason', () => {
    const expected = {
      'nfw.declared_deny_tcp.safe': ['declared_tcp_deny_required', 'network'],
      'nfw.declared_deny_udp.safe': ['declared_udp_deny_required', 'network'],
      'nfw.connection_limit.safe': ['declared_connection_limit_required', 'connection_limits'],
      'waf.rate_limit_canary.validation': ['declared_rate_limit_canary_required', 'rate_limit'],
      'nfw.origin_lockdown.safe': ['declared_origin_lockdown_required', 'origin'],
      'l3.basic_deny_rule.safe': ['port_or_declared_deny_required', 'network'],
      'l3.tcp_flag_anomaly.readiness': ['port_required', 'network'],
    };
    for (const [checkId, [reason, section]] of Object.entries(expected)) {
      const item = serverItem(getCheckById(checkId), EMPTY);
      assert.equal(item.requires_additional_input, false, `${checkId} is never withheld`);
      // The copy is still reachable from a server refusal of the same code.
      const prerequisite = checkPrerequisite(item, { serverRunnable: { runnable: false, reason } });
      assert.equal(prerequisite.reason, reason);
      assert.equal(prerequisite.label, ADDITIONAL_INPUT_REASON_COPY[reason].label);
      assert.equal(prerequisiteSection(prerequisite), section);
      assert.ok(prerequisiteCta(prerequisite));
      assert.equal(prerequisiteTone(prerequisite), 'warn');
    }
    assert.equal(controlsHref('tgt_fqdn', 'origin'), '#target-detail?id=tgt_fqdn&tab=controls&section=origin');
  });

  it('offers declaration-gated checks in the launcher with their reason, and drops ones no target can fix', () => {
    const udp = serverItem(getCheckById('nfw.declared_deny_udp.safe'), EMPTY);
    const soc = { ...getCheckById('waf.body_json_marker.soc') ?? CHECK_CATALOG.find((check) => check.check_id === 'waf.body_json_marker.soc'), requires_additional_input: true, additional_input_reason: 'invalid_check_definition' };
    const merged = withTargetDependentChecks([], [[udp, soc]]);
    assert.deepEqual(merged.map((check) => check.check_id), ['nfw.declared_deny_udp.safe']);
  });

  it('keeps unknown or loading answers neutral', () => {
    const deny = getCheckById('nfw.declared_deny_tcp.safe');
    const loading = checkPrerequisite(deny, { declarations: EMPTY });
    assert.equal(loading.state, 'checking');
    assert.equal(prerequisiteTone(loading), 'muted');
    const unknown = checkPrerequisite(deny, { serverRunnable: { runnable: false, reason: 'brand_new_code' } });
    assert.equal(unknown.label, 'Needs setup');
    assert.equal(prerequisiteSection(unknown), '');
  });
});

describe('replay re-grade', () => {
  it('names a re-grade with current signatures', () => {
    const model = verdictReplayModel({ stored: { verdict: 'protected' }, rederived: { verdict: 'protected', evidence_available: true }, changed: false, regraded: true });
    assert.equal(model.regrade.label, REGRADED_LABEL);
    assert.equal(REGRADED_LABEL, 'Re-graded with current signatures');
  });

  it('says only the verdict logic was re-applied, with the reason in words', () => {
    const payload = buildVerdictReplay({ run: { id: 'run_demo', check_id: 'nfw.declared_deny_tcp.safe' } });
    assert.equal(payload.regraded, false);
    assert.equal(payload.regrade_unavailable_reason, 'missing_response_features');
    const model = regradeModel(payload);
    assert.equal(model.regraded, false);
    assert.match(model.note, /did not store response details/);
    assert.match(model.note, /Only the verdict logic was re-applied/);
    assert.match(regradeModel({ regraded: false, regrade_unavailable_reason: 'insufficient_feature_data' }).note, /lack the status code/);
    assert.match(regradeModel({ regraded: false, regrade_unavailable_reason: 'something_new' }).note, /could not be graded again/);
    assert.equal(regradeModel({ stored: null }), null, 'older servers that do not say stay silent');
  });
});

describe('fix-verified closure basis', () => {
  it('reads the basis from the finding, else from the matching audit event', () => {
    assert.equal(fixVerifiedBasis({ status: 'fix_verified', verification_basis: 'violation_not_reproduced' }).label, 'Fixed — violation no longer reproduced (same perspective, ≥2 agreeing samples, all declared ports probed)');
    assert.equal(fixVerifiedBasis({ status: 'fix_verified', verification_basis: 'passing_retest' }).label, 'Fixed — passing retest');
    const audit = [
      { action: 'finding.fix_verified', ts: '2030-01-01T00:00:00Z', metadata: { verifying_run_id: 'run_old', verification_basis: 'passing_retest' } },
      { action: 'finding.updated', ts: '2030-01-03T00:00:00Z', metadata: { status: 'open' } },
      { action: 'finding.fix_verified', ts: '2030-01-04T00:00:00Z', metadata: { verifying_run_id: 'run_new', verification_basis: 'violation_not_reproduced' } },
    ];
    assert.deepEqual(fixVerifiedBasis({ status: 'fix_verified', verifying_run_id: 'run_old' }, audit), { basis: 'passing_retest', label: FIX_VERIFIED_BASIS_LABELS.passing_retest, source: 'audit' });
    assert.equal(fixVerifiedBasis({ status: 'fix_verified' }, audit).basis, 'violation_not_reproduced', 'newest event without a run to match');
    assert.deepEqual(fixVerifiedBasis({ status: 'fix_verified' }, []), { basis: '', label: FIX_VERIFIED_BASIS_UNKNOWN, source: '' });
  });

  it('labels the audit row with the basis', () => {
    assert.equal(formatAuditAction('finding.fix_verified', 'x', { verification_basis: 'violation_not_reproduced' }), FIX_VERIFIED_BASIS_LABELS.violation_not_reproduced);
    assert.equal(formatAuditAction('finding.fix_verified', 'x', { verification_basis: 'passing_retest' }), 'Fixed — passing retest');
  });
});

describe('custom canary members follow their own run', () => {
  const recent = new Date(Date.UTC(2030, 0, 1, 12)).toISOString();
  const nowMs = Date.UTC(2030, 0, 1, 13);
  const coverage = {
    custom_canary_rollups: [{
      check_id: 'waf.crlf_injection_marker.safe',
      rolled_up_pairs: [
        { check_id: 'waf.crlf_injection_marker.safe', last_run_id: 'run_a', state: 'conclusive', fresh: true, version_gap: null, verdict: 'exposed', observed_at: recent },
        { check_id: 'waf.open_redirect_marker.safe', last_run_id: 'run_b', state: 'partial', fresh: false, version_gap: 'signature_corpus_version_mismatch', verdict: 'protected', observed_at: recent },
      ],
    }],
  };
  const row = (checkId, runId, finishedAt = recent) => ({ checkId, runId, status: 'passed', finishedAt });

  it('applies the member answer only to the run it graded', () => {
    assert.equal(rowEvidenceState(row('waf.open_redirect_marker.safe', 'run_b'), { coverage, nowMs }), 'version_gap');
    assert.equal(rowEvidenceState(row('waf.open_redirect_marker.safe', 'run_newer'), { coverage, nowMs }), 'fresh', 'another run of the same check is judged on its own age');
    assert.equal(rowEvidenceState(row('waf.crlf_injection_marker.safe', 'run_a'), { coverage, nowMs }), 'fresh');
  });

  it('keeps unresolved member evidence unverified rather than inventing a version mismatch', () => {
    const unresolved = { custom_canary_rollups: [{ rolled_up_pairs: [{ check_id: 'waf.open_redirect_marker.safe', last_run_id: 'run_b', state: 'unknown', fresh: false, pair_reason: 'invalid_or_unresolved_evidence', verdict: 'exposed' }] }] };
    assert.equal(rowEvidenceState(row('waf.open_redirect_marker.safe', 'run_b'), { coverage: unresolved, nowMs }), 'unverified');
    const [member] = customCanaryMembers(unresolved);
    assert.equal(member.evidence, 'unverified');
    assert.equal(member.label, 'Unverified, not counted');
  });

  it('lists each member with the run it links to', () => {
    const members = customCanaryMembers(coverage);
    assert.deepEqual(members.map((member) => [member.checkId, member.runId, member.evidence]), [
      ['waf.crlf_injection_marker.safe', 'run_a', 'fresh'],
      ['waf.open_redirect_marker.safe', 'run_b', 'version_gap'],
    ]);
    assert.equal(members[1].label, 'Older check version, not counted');
    assert.deepEqual(customCanaryMembers(null), []);
  });
});

describe('provider observation evidence boundaries', () => {
  it('keeps unknown hosting neutral when an edge fingerprint is detected', () => {
    const source = readFileSync(new URL('../../apps/web/react/src/components/targets/domain-protection.tsx', import.meta.url), 'utf8');
    const observations = source.slice(source.indexOf('export function ProviderObservations('));
    const setup = observations.slice(observations.indexOf('const edgeProxyRow ='), observations.indexOf('\n  return ('));
    const rowStart = observations.indexOf('const statusLabel = row.statusLabel;');
    assert.ok(rowStart >= 0, 'provider status is preserved rather than inferred from another family');
    const rowCopy = observations.slice(rowStart, observations.indexOf('\n          return (', rowStart));
    const present = new Function('rows', 'row', 'formatDate', `${setup}\n${rowCopy}\nreturn { statusLabel, metaText };`);
    for (const [family, status] of [['cloud', 'not_detected'], ['cloud', 'not_recorded'], ['origin_hosting', 'unknown'], ['origin_hosting', 'not_recorded']]) {
      const row = { family, status, statusLabel: 'Unknown hosting' };
      const model = present([{ family: 'cdn', status: 'detected', providerName: 'Observed edge' }, row], row, () => 'time');
      assert.equal(model.statusLabel, row.statusLabel, `${family}/${status}`);
      assert.match(model.metaText, /edge fingerprint for Observed edge does not establish/);
      assert.doesNotMatch(`${model.statusLabel} ${model.metaText}`, /masked|Public traffic routes through/i);
    }
    const origin = { family: 'origin_hosting', status: 'unknown', statusLabel: 'Unknown' };
    const unnamed = present([{ family: 'cdn', status: 'detected' }, { family: 'dns', providerName: 'Unrelated DNS provider' }, origin], origin, () => 'time');
    assert.match(unnamed.metaText, /does not establish origin hosting, reachability, or lockdown/);
    assert.doesNotMatch(unnamed.metaText, /Unrelated DNS provider/);
  });
});

describe('origin lockdown prerequisite', () => {
  it('points the rule-coverage CTA at the origin controls section and explains the relation', async () => {
    useIsolatedDevDataDir();
    const { buildTargetRuleCoverage } = await import('../../src/services/ruleCoverage.mjs');
    const model = normalizeRuleCoverage(buildTargetRuleCoverage({ targetId: FQDN.id, declarations: EMPTY, env: {} }));
    const origin = model.categories.find((category) => category.id === 'origin_lockdown');
    assert.ok(origin);
    assert.deepEqual(origin.ctas.map((cta) => [cta.key, cta.section]), [['origin.lockdown_expected', 'origin'], ['origin_binding', 'origin_relations']]);
    assert.match(DECLARATION_KEYS['origin.lockdown_expected'].unlocks, /origin relation/);
    assert.match(ADDITIONAL_INPUT_REASON_COPY.declared_origin_lockdown_required.detail, /origin relation/);
  });
});
