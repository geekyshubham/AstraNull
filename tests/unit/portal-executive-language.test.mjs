import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  dashboardReadinessMessage,
  EXPECTED_VERDICT_LABELS,
  evidenceModePresentation,
  evidenceTierInfo,
  plainCheckName,
  plainCodeLabel,
  plainEmptyReason,
  plainExpectedVerdictLabel,
  plainFindingTitle,
  plainInlineText,
  plainProtectionLabel,
  plainVerdictLabel,
  plainVerdictShortLabel,
  plainVerificationLabel,
} from '../../apps/web/react/src/lib/plain-language.mjs';

const DASHBOARD_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/dashboard-page.tsx', import.meta.url),
  'utf8',
);
const TARGET_SOURCE = readFileSync(
  new URL('../../apps/web/react/src/pages/target-detail-view.tsx', import.meta.url),
  'utf8',
);

describe('portal executive language', () => {
  it('translates security verdicts without weakening or strengthening the result', () => {
    assert.equal(plainVerdictLabel('penetrated'), 'Attack traffic reached your server');
    assert.equal(plainVerdictLabel('bypassable'), 'A bypass path reached your server');
    assert.equal(plainVerdictLabel('protected'), 'Protection stopped the test traffic');
    assert.equal(plainVerdictLabel('inconclusive'), 'Not enough evidence');
  });

  it('keeps known acronyms uppercase in machine-code labels', () => {
    assert.equal(plainCodeLabel('oidc_prod_auth_preflight'), 'OIDC prod auth preflight');
    assert.equal(plainCodeLabel('ui_accessibility_matrix'), 'UI accessibility matrix');
    assert.equal(plainCodeLabel('dr_restore'), 'DR restore');
    assert.equal(plainCodeLabel('kms_vault_posture'), 'KMS vault posture');
    assert.equal(plainCodeLabel('observability_slo'), 'Observability SLO');
    assert.equal(plainCodeLabel('staging_e2e_matrix'), 'Staging E2E matrix');
    assert.equal(plainCodeLabel('tenant_id'), 'Tenant ID');
    assert.equal(plainCodeLabel('soc_gated'), 'SOC-gated');
    assert.equal(plainCodeLabel('missing_evidence'), 'Missing evidence');
    assert.equal(plainCodeLabel(''), 'Not reported');
    assert.equal(plainInlineText('Runs are soc_gated here.'), 'Runs are SOC-gated here.');
  });

  it('gives ownership and protection states plain labels', () => {
    assert.equal(plainVerificationLabel('user_confirmed'), 'Owner confirmed');
    assert.equal(plainVerificationLabel('dns_verified'), 'Domain ownership verified');
    assert.equal(plainProtectionLabel('edge_protected'), 'Blocked at the edge only');
    assert.equal(plainProtectionLabel('underprotected'), 'Protection needs work');
  });

  it('defines all five evidence tiers in increasing operational context', () => {
    assert.equal(evidenceTierInfo('E1')?.label, 'Declared only');
    assert.equal(evidenceTierInfo('e2 transport')?.label, 'Connection observed');
    assert.equal(evidenceTierInfo('E3')?.label, 'Behavior observed');
    assert.equal(evidenceTierInfo('E4')?.label, 'SOC-governed');
    assert.equal(evidenceTierInfo('E5')?.label, 'Monitoring only');
  });

  it('never presents metadata markers or E1 declarations as live tests', () => {
    for (const record of [
      { probe_kind: 'metadata_marker', evidence_ids: ['evt_1'] },
      { evidence_tier: 'E1', last_run_id: 'run_1', last_verdict: 'pass' },
    ]) {
      const presentation = evidenceModePresentation(record);
      assert.equal(presentation.label, 'Declaration only');
      assert.equal(presentation.live, false);
      assert.match(presentation.detail, /No live traffic/);
    }
  });

  it('claims a live test only when a live-capable tier or probe also has cited evidence', () => {
    assert.equal(evidenceModePresentation({ evidence_tier: 'E3' }).label, 'Bounded live check available');
    assert.equal(
      evidenceModePresentation({ evidence_tier: 'E3', run_id: 'run_1', verdict: 'protected' }).label,
      'Bounded live check available',
      'a verdict without a cited evidence id must not be presented as tested live',
    );
    assert.equal(
      evidenceModePresentation({ evidence_tier: 'E3', run_id: 'run_1', verdict: 'protected', evidence_ids: ['evt_1'] }).label,
      'Tested live (bounded)',
    );
    assert.equal(
      evidenceModePresentation({ evidence_ids: ['evt_1'] }).label,
      'Evidence recorded',
      'evidence without tier or probe kind must not be promoted to live',
    );
  });

  it('maps machine-coded empty reasons while preserving authored sentences', () => {
    assert.equal(
      plainEmptyReason('coverage_summary_not_populated'),
      'WAF coverage will appear after a declared WAF asset records evidence.',
    );
    assert.equal(plainEmptyReason('No targets are declared yet.'), 'No targets are declared yet.');
    assert.equal(plainEmptyReason('future_reason_code'), 'Future reason code.');
  });

  it('resolves generated finding titles to a plain verdict and target hostname', () => {
    const finding = {
      title: 'Finding: penetrated on tgt_1234',
      target_id: 'tgt_1234',
      check_id: 'origin.leak_scan.safe',
    };
    assert.equal(
      plainFindingTitle(
        finding,
        [{ id: 'tgt_1234', value: 'astranull.site' }],
        [{ check_id: 'origin.leak_scan.safe', name: 'Origin bypass check' }],
      ),
      'Attack traffic reached your server on astranull.site',
    );
    assert.equal(
      plainFindingTitle({
        title: 'Finding: edge_exposed on api.example.com',
        target_id: 'tgt_api',
        check_id: 'origin.leak_scan.safe',
      }),
      'Direct server access was found on api.example.com',
      'the backend-generated hostname form must not leak a machine-coded verdict',
    );
    assert.equal(plainCheckName('WAF/API-Gateway marker'), 'WAF application gateway marker');
  });

  it('derives declaration-only versus bounded-live copy from the loaded check catalog', () => {
    assert.equal(
      evidenceModePresentation(
        { id: 'run_1', verdict: { verdict: 'inconclusive', evidence_ids: ['evd_1'] } },
        { probe_profile: { kind: 'metadata_marker' } },
      ).label,
      'Declaration only',
    );
    const live = evidenceModePresentation(
      { id: 'run_2', verdict: { verdict: 'inconclusive', evidence_ids: ['evd_2'] } },
      { probe_profile: { kind: 'http_bounded' } },
    );
    assert.equal(live.label, 'Tested live (bounded)');
    assert.equal(live.live, true);
    assert.equal(
      evidenceModePresentation({ id: 'run_3', evidence_ids: ['evd_3'] }).label,
      'Evidence recorded',
      'unknown methods must not be promoted to live',
    );
  });

  it('humanizes embedded machine tokens without changing supported record and check IDs', () => {
    assert.equal(
      plainInlineText('Missing customer_authorization_letter for run_123 on origin.leak_scan.safe.'),
      'Missing customer authorization letter for run_123 on origin.leak_scan.safe.',
    );
    assert.equal(plainInlineText('signup_request is absent'), 'Signup request is absent');
  });

  it('qualifies readiness by evidence coverage and high-priority gaps', () => {
    assert.match(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 1, coveragePercent: 100 }).headline,
      /Not ready yet/,
    );
    assert.match(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 0, coveragePercent: 50 }).headline,
      /Partly ready/,
    );
    assert.equal(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 0, coveragePercent: 100 }).headline,
      'Ready for the scenarios tested',
    );
    assert.doesNotMatch(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 0, coveragePercent: 100 }).headline,
      /^Ready for a DDoS attack$/,
    );
  });

  it('says no score yet instead of a partial verdict when nothing has been validated', () => {
    const empty = dashboardReadinessMessage({ score: 0, coveragePercent: null, hasEvidence: false });
    assert.equal(empty.headline, 'No readiness score yet');
    assert.equal(empty.tone, 'muted');
    assert.doesNotMatch(empty.headline, /Partly ready|Passed this check/);
    assert.equal(
      dashboardReadinessMessage({ dataUnavailable: true, hasEvidence: false }).headline,
      'Readiness is not known yet',
      'unavailable data still wins over the empty state',
    );
  });

  it('counts open high-priority findings without calling them gaps', () => {
    const one = dashboardReadinessMessage({ score: 95, highPriorityFindings: 1, coveragePercent: 100 });
    assert.equal(one.headline, 'Not ready yet: 1 high-priority finding is open');
    assert.doesNotMatch(one.headline, /gap/i);
    assert.equal(one.detail, 'Resolve the open findings below, then run the same checks again.');
    assert.equal(
      dashboardReadinessMessage({ score: 95, highPriorityFindings: 3, coveragePercent: 100 }).headline,
      'Not ready yet: 3 high-priority findings are open',
    );
  });

  it('keeps catalog check names that contain API unchanged', () => {
    assert.equal(plainCheckName('API Surface Scan (Safe)'), 'API Surface Scan (Safe)');
    assert.equal(plainCheckName('Batch API Limit Readiness (Safe)'), 'Batch API Limit Readiness (Safe)');
    assert.equal(plainCheckName('L7/API flood readiness'), 'application layer flood readiness');
  });

  it('maps verdicts to short pill labels and keeps full sentences as the subline', () => {
    for (const verdict of ['protected', 'pass', 'passed', 'edge_protected', 'allowed_as_expected']) {
      assert.equal(plainVerdictShortLabel(verdict), 'Protected', verdict);
    }
    for (const verdict of ['bypassable', 'penetrated', 'exposed', 'edge_exposed', 'gap', 'fail', 'failed']) {
      assert.equal(plainVerdictShortLabel(verdict), 'Gap found', verdict);
    }
    assert.equal(plainVerdictShortLabel('inconclusive'), 'Inconclusive');
    assert.equal(plainVerdictShortLabel('unknown'), 'Inconclusive');
    assert.equal(plainVerdictShortLabel('review'), 'Needs review');
    assert.equal(plainVerdictShortLabel('rate_limited_partially'), 'Rate limited partially');
    assert.equal(plainVerdictLabel('protected'), 'Protection stopped the test traffic');
  });

  it('labels expected verdicts as expectations, not outcomes', () => {
    assert.equal(plainExpectedVerdictLabel('pass'), 'Expect protection to hold');
    assert.equal(plainExpectedVerdictLabel('warn'), 'Expect a warning');
    assert.equal(plainExpectedVerdictLabel('fail'), 'Expect a gap');
    assert.equal(plainExpectedVerdictLabel('manual_review'), 'Needs review (observation only)');
    assert.equal(plainExpectedVerdictLabel('custom_value'), 'Custom value');
    assert.equal(Object.isFrozen(EXPECTED_VERDICT_LABELS), true);
  });

  it('labels URL, IP and CIDR target kinds in plain words', () => {
    assert.equal(plainCodeLabel('url'), 'URL');
    assert.equal(plainCodeLabel('ip'), 'IP address');
    assert.equal(plainCodeLabel('cidr'), 'CIDR range');
  });

  it('keeps executive and target summaries evidence-aware in source', () => {
    // Current release: the browser-inferred defense-path diagram is gone; priorities lead and the
    // readiness score carries its scope. Target summaries come from recorded family rows.
    assert.doesNotMatch(DASHBOARD_SOURCE, /Where does attack traffic get stopped\?|buildDefensePath/);
    assert.match(DASHBOARD_SOURCE, /What to fix first/);
    assert.match(DASHBOARD_SOURCE, /dashboardReadinessMessage/);
    assert.match(DASHBOARD_SOURCE, /not a protection guarantee/i);
    assert.match(TARGET_SOURCE, /providerFamilyRows\(/);
    assert.match(TARGET_SOURCE, /Protection observations|ProviderObservations/);
    assert.match(TARGET_SOURCE, /evidenceModePresentation/);
  });
});

describe('QA swarm 2026-10-01 regressions', () => {
  const read = (rel) => readFileSync(new URL(`../../apps/web/react/src/${rel}`, import.meta.url), 'utf8');

  it('gates the dashboard validation CTA behind canStartRun (RBAC-01)', () => {
    const source = read('pages/dashboard-page.tsx');
    assert.match(source, /import \{ canStartRun \} from '\.\.\/lib\/run-permissions\.mjs'/);
    // The CTA only renders for roles that actually hold test_run:start, and leads to a target
    // (validation is target-first; there is no standalone run page in the current release).
    assert.match(source, /canStartRun\(session\.role\) \?[\s\S]*?href="#targets"[\s\S]*?Validate a target/);
    assert.doesNotMatch(source, /href="#runs"/);
  });

  it('makes the Reports nav copy truthful — no WAF/release promise (WAF-CDN-02)', () => {
    const nav = read('lib/navigation.ts');
    const manifest = read('lib/prototype-manifest.ts');
    assert.doesNotMatch(nav, /release, and WAF report builders/);
    assert.match(nav, /Executive, technical, (?:SOC, )?audit, and compliance report builders\./);
    assert.doesNotMatch(
      manifest,
      /routeId: 'reports',[\s\S]*?summary: 'Executive, technical, SOC, audit, release, and WAF report builders\.'/,
    );
  });

  it('describes WAF posture as external-probe evidence, not internal agents (EVIDENCE-01)', () => {
    const panel = read('components/dashboard/waf-summary-panel.tsx');
    assert.doesNotMatch(panel, /agent-confirmed/);
    assert.doesNotMatch(panel, /internal corroboration/);
    assert.match(panel, /Confirmed by external probe evidence/);
  });

  it('offers an unambiguous Keep run dismiss on cancel-run dialogs (RUNS-01)', () => {
    const crud = read('lib/crud-ui.tsx');
    // ConfirmModal supports an explicit dismiss label (defaulting to Cancel for other callers).
    assert.match(crud, /dismissLabel = 'Cancel'/);
    assert.match(crud, /onClick=\{onCancel\}>\{dismissLabel\}<\/Button>/);
    for (const rel of ['pages/functional-surfaces.tsx', 'pages/detail-pages.tsx']) {
      const source = read(rel);
      // Cancel-run dialog pairs "Keep run" (dismiss) with "Cancel run" (confirm).
      assert.match(source, /confirmLabel="Cancel run"\s*\n\s*dismissLabel="Keep run"/);
    }
  });
});
