import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { CHECK_CATALOG, checkAdditionalInputReason, checkRequiresAdditionalInput, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import { checkExclusionReason, checkSupportsTarget, withTargetDependentChecks } from '../../apps/web/react/src/lib/check-picker.mjs';
import { ADDITIONAL_INPUT_REASON_COPY, checkPrerequisite, controlsHref, needsTargetAnswer, targetRunnableIndex } from '../../apps/web/react/src/lib/control-declarations.mjs';
import {
  ROW_STATUS_META,
  assessmentChecks,
  buildCheckRows,
  groupRowsByCategory,
  isDeclarationOnlyCheck,
  withTargetRunnableChecks,
} from '../../apps/web/react/src/lib/domain-checks.mjs';
import { normalizeEvidenceContext, fallbackContextFromRecord } from '../../apps/web/react/src/lib/evidence-inspector.mjs';
import { generateCheckProbeLogs } from '../../apps/web/react/src/lib/live-probe-logs.mjs';
import {
  NOT_TESTED_LABEL,
  REQUIRED_INPUT_MISSING,
  notTestedSentence,
  requiredInputMissing,
  requiredInputMissingHref,
} from '../../apps/web/react/src/lib/missing-input.mjs';

const DOMAIN = { id: 'tgt_demo', kind: 'fqdn', value: 'shop.example.com', tenant_id: 'tenant_demo' };
const DEMO_ENV = { ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: 'tenant_demo' };
const SERVER_MESSAGE = 'No denied port is declared, so there was nothing to probe.';

function targetCatalog(env) {
  return CHECK_CATALOG.map((check) => {
    const options = { target: DOMAIN, tenantId: DOMAIN.tenant_id, env };
    const requires = checkRequiresAdditionalInput(check, options);
    return { ...check, requires_additional_input: requires, additional_input_reason: requires ? checkAdditionalInputReason(check, options) : null };
  });
}

function missingInputRun(overrides = {}) {
  return {
    id: 'run_missing',
    tenant_id: 'tenant_demo',
    target_id: DOMAIN.id,
    check_id: 'nfw.declared_deny_tcp.safe',
    status: 'verdicted',
    started_at: '2030-01-01T00:00:00Z',
    completed_at: '2030-01-01T00:00:01Z',
    summary: { requests_sent: 0, required_input_missing: 'declared_tcp_deny_required' },
    verdict: { verdict: 'inconclusive', confidence: 'external_only', explanation: SERVER_MESSAGE, explanation_reason: REQUIRED_INPUT_MISSING, evidence_ids: [] },
    ...overrides,
  };
}

describe('required_input_missing result copy', () => {
  it('prefers the server message and maps the missing input to its Controls section', () => {
    const info = requiredInputMissing(missingInputRun());
    assert.equal(info.label, NOT_TESTED_LABEL);
    assert.equal(info.message, SERVER_MESSAGE);
    assert.equal(info.serverMessage, true);
    assert.equal(info.reason, 'declared_tcp_deny_required');
    assert.equal(info.section, ADDITIONAL_INPUT_REASON_COPY.declared_tcp_deny_required.section);
    assert.equal(info.cta, ADDITIONAL_INPUT_REASON_COPY.declared_tcp_deny_required.cta);
    assert.equal(info.tone, 'muted', 'a missing input is not a failure');
    assert.equal(requiredInputMissingHref(info, DOMAIN.id), controlsHref(DOMAIN.id, 'network'));
  });

  it('falls back to plain copy naming the input when the server sent no message', () => {
    const info = requiredInputMissing(missingInputRun({ verdict: { verdict: 'inconclusive', explanation_reason: REQUIRED_INPUT_MISSING } }));
    assert.equal(info.message, 'Not tested — this check needs a declared TCP deny rule on the target, so nothing was sent.');
    assert.equal(info.serverMessage, false);
    assert.equal(notTestedSentence('port_required'), 'Not tested — this check needs a port on the target, so nothing was sent.');
    assert.equal(notTestedSentence('two_perspectives_required'), 'Not tested — this check needs two perspectives, so nothing was sent.');
    assert.equal(notTestedSentence('something_new'), 'Not tested — this check needs more input, so nothing was sent.');
  });

  it('reads the reason from the verdict, the run summary, placement or an evidence answer, and maps alias codes', () => {
    assert.ok(requiredInputMissing({ summary: { required_input_missing: 'port_required' } }));
    assert.ok(requiredInputMissing({ verdict: { verdict: 'inconclusive', placement_confidence: { reason: REQUIRED_INPUT_MISSING } } }));
    const answer = requiredInputMissing({ explanation_reason: REQUIRED_INPUT_MISSING, required_input: 'missing_declared_origin_binding', explanation: 'x' });
    assert.equal(answer.reason, 'origin_binding_required');
    assert.equal(answer.section, 'origin_relations');
    const unmapped = requiredInputMissing({ explanation_reason: REQUIRED_INPUT_MISSING });
    assert.equal(unmapped.section, '');
    assert.equal(requiredInputMissingHref(unmapped, DOMAIN.id), '', 'no Controls link when the input cannot be mapped');
  });

  it('ignores other inconclusive results', () => {
    assert.equal(requiredInputMissing({ verdict: { verdict: 'inconclusive', explanation_reason: 'probe_timeout' } }), null);
    assert.equal(requiredInputMissing({ verdict: { verdict: 'protected' } }), null);
    assert.equal(requiredInputMissing(null), null);
  });

  it('shows a target check row as Not tested with a neutral tone, outside the inconclusive count', () => {
    const check = CHECK_CATALOG.find((item) => item.check_id === 'nfw.declared_deny_tcp.safe');
    const [row] = buildCheckRows({ checks: [check], runs: [missingInputRun()] });
    assert.equal(row.status, 'not_tested');
    assert.equal(row.label, ROW_STATUS_META.not_tested.label);
    assert.equal(row.tone, 'muted');
    assert.equal(row.explanation, SERVER_MESSAGE);
    assert.equal(row.missingInput.section, 'network');
    const [group] = groupRowsByCategory([row]);
    assert.equal(group.counts.not_tested, 1);
    assert.equal(group.counts.inconclusive, 0);
    const verdictLog = generateCheckProbeLogs(row, DOMAIN.value, []).find((entry) => entry.tag === 'NOT TESTED');
    assert.ok(verdictLog, 'the probe log names the outcome in plain words');
    assert.doesNotMatch(verdictLog.message, /not_tested|inconclusive/);
  });

  it('reads a scan step that carries the reason on its verdict', () => {
    const check = CHECK_CATALOG.find((item) => item.check_id === 'nfw.declared_deny_tcp.safe');
    const step = { check_id: check.check_id, status: 'verdicted', test_run_id: 'run_missing', requests_sent: 0, verdict: { verdict: 'inconclusive', explanation: SERVER_MESSAGE, explanation_reason: REQUIRED_INPUT_MISSING } };
    const [row] = buildCheckRows({ checks: [check], scan: { steps: [step] } });
    assert.equal(row.status, 'not_tested');
    assert.equal(row.explanation, SERVER_MESSAGE);
  });

  it('carries the reason and missing input into the evidence inspector answer', () => {
    const ref = { entry: 'check_result', target_id: DOMAIN.id, check_id: 'nfw.declared_deny_tcp.safe', test_run_id: 'run_missing' };
    const fallback = fallbackContextFromRecord(ref, missingInputRun());
    const model = normalizeEvidenceContext(fallback.payload, ref);
    assert.equal(model.answer.reason, REQUIRED_INPUT_MISSING);
    assert.equal(model.answer.requiredInput, 'declared_tcp_deny_required');
    const info = requiredInputMissing({ explanation_reason: model.answer.reason, required_input: model.answer.requiredInput, explanation: model.answer.explanation });
    assert.equal(info.message, SERVER_MESSAGE);
    assert.equal(info.section, 'network');
  });
});

describe('demo tenant check list: the UI follows requires_additional_input only', () => {
  const demo = targetCatalog(DEMO_ENV);
  const standard = targetCatalog({});
  const runnable = demo.filter((check) => isCustomerRunnable(check) && !checkExclusionReason(check));
  const targetDependent = runnable.filter((check) => needsTargetAnswer(check));

  it('reports every customer-runnable check as runnable for the demo tenant', () => {
    assert.ok(targetDependent.length > 0);
    assert.ok(runnable.every((check) => check.requires_additional_input === false && check.additional_input_reason === null));
  });

  it('marks every customer-runnable check ready in the picker with no declarations, demo or not', () => {
    for (const catalog of [demo, standard]) {
      const index = targetRunnableIndex(catalog);
      for (const check of runnable) {
        assert.equal(checkPrerequisite(check, { serverRunnableIndex: index }).state, 'ready', check.check_id);
      }
    }
  });

  it('adds target-dependent checks to the launcher list and the target run set when the server says runnable', () => {
    const added = withTargetDependentChecks([], [demo]).map((check) => check.check_id);
    for (const check of targetDependent) assert.ok(added.includes(check.check_id), check.check_id);
    const context = { serverRunnableIndex: targetRunnableIndex(demo) };
    const assessment = assessmentChecks(withTargetRunnableChecks([], demo), DOMAIN, context).map((check) => check.check_id);
    const expected = targetDependent.filter((check) => checkSupportsTarget(check, DOMAIN) && !isDeclarationOnlyCheck(check));
    assert.ok(expected.length > 0);
    for (const check of expected) assert.ok(assessment.includes(check.check_id), check.check_id);
  });

  it('has no demo-specific gating in the picker, launcher or target check logic', () => {
    for (const file of [
      'apps/web/react/src/lib/check-picker.mjs',
      'apps/web/react/src/lib/control-declarations.mjs',
      'apps/web/react/src/lib/domain-checks.mjs',
      'apps/web/react/src/components/runs/check-picker.tsx',
      'apps/web/react/src/components/runs/validation-scan-launcher.tsx',
    ]) {
      assert.doesNotMatch(readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8'), /demo/i, file);
    }
  });
});
