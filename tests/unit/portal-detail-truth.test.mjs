import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const source = readFileSync('apps/web/react/src/pages/detail-pages.tsx', 'utf8');
const functionalSurfaces = readFileSync('apps/web/react/src/pages/functional-surfaces.tsx', 'utf8');
const targetDetail = readFileSync('apps/web/react/src/pages/target-detail-view.tsx', 'utf8');
const statusTone = readFileSync('apps/web/react/src/lib/status-tone.ts', 'utf8');

function sourceBetween(value, start, end) {
  const from = value.indexOf(start);
  const to = value.indexOf(end, from + start.length);
  assert.notEqual(from, -1, `missing source marker: ${start}`);
  assert.notEqual(to, -1, `missing source marker: ${end}`);
  return value.slice(from, to);
}

describe('portal detail truth labels', () => {
  it('distinguishes metadata, operations, live, and request-only execution', () => {
    assert.match(source, /Metadata evaluation', cap: 'No network I\/O'/);
    assert.match(source, /Operations self-check', cap: '1 self-check'/);
    assert.match(source, /maxRequests === 1 \? '1 probe operation' : `Up to \$\{maxRequests\} probe operations`/);
    assert.match(source, /up to two DNS destination-vetting resolver operations per hostname destination/);
    assert.match(source, /cap: checkProbeOperationBoundLabel\(maxRequests\)/);
    assert.match(source, /Request only', cap: 'No customer execution'/);
    assert.doesNotMatch(source, /maxRequests === 1\) return 'metadata'/);
  });

  it('renders every documented taxonomy family with plural-first resources', () => {
    for (const field of [
      'attack_vector_ids',
      'exhausted_resources',
      'exhausted_resource',
      'delivery_patterns',
      'waf_vulnerability_ids',
      'non_ddos_threat_ids',
    ]) assert.match(source, new RegExp(`check\\.${field}`));
    assert.match(source, /pluralResources\.length > 0 \? pluralResources : toList\(check\.exhausted_resource\)/);
    assert.match(source, /Values are shown as stored, without broadening or truncation/);
  });

  it('uses danger tones for adverse verdict vocabulary', () => {
    assert.match(source, /verdictTone\(/);
    for (const verdict of ['edge_exposed', 'bypassable', 'penetrated', 'exposed', 'unprotected']) {
      assert.match(statusTone, new RegExp(`GAP_VERDICTS = \\[[^\\]]*'${verdict}'`), verdict);
    }
  });

  it('omits unsupported agent aliases from global and current-group run tables', () => {
    const globalRunColumns = sourceBetween(
      functionalSurfaces,
      "if (route === 'runs')",
      'const canOpenVectorLibrary =',
    );


    for (const tableSource of [globalRunColumns, targetDetail]) {
      assert.doesNotMatch(tableSource, /observed_agent_id|agentId|agent_id/);
      assert.doesNotMatch(tableSource, /label:\s*['"]Agent['"]/);
    }
  });

  it('keys run-event evidence by entity and never converts load failures into authoritative emptiness', () => {
    assert.match(source, /type RunEventEvidenceState = \{[\s\S]*?entityId: string;[\s\S]*?status: 'loading' \| 'loaded' \| 'error'/);
    assert.match(source, /runEventState\.entityId === entityId[\s\S]*?\? runEventState[\s\S]*?: \{ entityId, status: 'loading', items: \[\], error: '' \}/);
    assert.match(source, /setRunEventState\(\{ entityId: requestedEntityId, status: 'loading', items: \[\], error: '' \}\)/);
    assert.match(source, /status: 'loaded',[\s\S]*?items: \(payload as \{ items: DataItem\[\] \}\)\.items/);
    assert.match(source, /if \(cancelled\) return;[\s\S]*?status: 'error',[\s\S]*?error: 'Run event evidence unavailable\.'/);
    assert.match(source, /runEventState=\{visibleRunEventState\}/);
    assert.match(source, /runEventEvidenceUnavailable \? \([\s\S]*?Probe event evidence unavailable\.[\s\S]*?: probeEvents\.length === 0/);
    assert.match(source, /runEventEvidenceUnavailable \? \([\s\S]*?Correlation evidence unavailable because run event evidence could not be loaded\.[\s\S]*?<VerdictExplanationPanel/);
    assert.doesNotMatch(source, /\.catch\(\(\) => \{[\s\S]{0,100}setRunEvents\(\[\]\)/);
  });

  it('describes digest recomputation as local and makes no server-verification claim', () => {
    assert.match(source, />Compute local digest<\/Button>/);
    assert.match(source, /<span>Recorded hash<\/span>/);
    assert.match(source, /<span>Locally computed \(this page\)<\/span>/);
    assert.match(source, /\/v1\/evidence-context\?entry=artifact&evidence_id=/);
    assert.match(source, /const serverVerified = integrityState\.status === 'ready' && integrityState\.value === 'verified';/);
    assert.match(source, /'Not verified \(recorded hash only\)'/);
    assert.match(source, /'Verification status unavailable'/);
    assert.doesNotMatch(source, /getString\(entity, \['verified'\]/);
    assert.doesNotMatch(source, /const byRun =/);
    assert.doesNotMatch(source, /custodyLabel/);
    assert.match(source, /'Not verified: no authoritative verification succeeded'/);
    assert.match(source, /No server verification request was made/);
    assert.match(source, /recorded artifact digest may cover different sealed bytes/);
    assert.match(source, /no comparison or server verification was performed/);
    assert.doesNotMatch(source, /matched the recorded artifact digest/);
    assert.doesNotMatch(source, /Full custody-chain verification runs server-side/);
  });

  it('states what an evidence artifact supports from recorded relationships only', () => {
    const evidence = sourceBetween(source, 'function EvidenceDetailView(', 'function HighScaleDetailView(');
    assert.match(evidence, /requestJson\(config, session, `\/v1\/test-runs\/\$\{encodeURIComponent\(linkedRunId\)\}`\)/);
    assert.match(evidence, /return \(\) => \{ cancelled = true; \};\n  \}, \[linkedRunId, config, session, runContextReload\]\);/);
    assert.match(evidence, /<CardTitle>What this evidence supports<\/CardTitle>/);
    for (const fallback of ['Relationship not recorded', 'Not visible to your role', 'Unavailable']) {
      assert.match(evidence, new RegExp(`'${fallback}'`), fallback);
    }
    assert.match(evidence, /`\$\{supportCheckName\} result on \$\{supportHost\}`/);
    assert.match(evidence, /\{supportVerdict \? <div><span>Recorded verdict<\/span>/);
    assert.doesNotMatch(evidence, /Expected behavior|Observed behavior/);
    assert.match(evidence, /<span>Recorded by run<\/span>\{runId \? <DetailEntityLink route="run-detail" id=\{runId\} \/>/);
    assert.doesNotMatch(evidence, /Recorded by run \$\{runId\}/);
    assert.doesNotMatch(evidence, />Back to finding<\/AnchorButton>/);
    assert.match(evidence, /\? \{ label: 'finding', href: buildDetailHref\('finding-detail', findingId\) \}[\s\S]*?\? \{ label: 'run', href: buildDetailHref\('run-detail', runId\) \}/);
    assert.doesNotMatch(evidence, /formatDate\((sealedAtRaw|recordedAtRaw|integrityState\.verifiedAt)\)/);
  });

  it('keeps run detail inside its target and uses plain run vocabulary', () => {
    const run = sourceBetween(source, 'function RunDetailView(', 'function TenantDetailView(');
    assert.match(run, /backLink=\{runTargetId \? \{ label: runTargetValue \|\| 'target', href: runTargetHref \} : undefined\}/);
    assert.match(run, /&tab=validate&check=\$\{encodeURIComponent\(runCheckId\)\}/);
    assert.match(run, /<span>Schedule<\/span>/);
    assert.match(run, /Not started by a schedule/);
    assert.match(run, / · started by a schedule/);
    assert.doesNotMatch(run, /Open evidence vault|#evidence"|scheduled policy/);
    assert.match(run, /Publishes a verdict from the signed probe evidence already recorded for this run\./);
    assert.match(run, /records no verdict\./);
    assert.match(run, /plainVerdictShortLabel\(verdictValue\)/);
    assert.doesNotMatch(source, /'Open test runs'/);
  });

  it('gives the SOC request a typed, danger-toned Start confirmation and an approve scope summary', () => {
    const soc = sourceBetween(source, 'function SocRequestDetailView(', 'function detailRowNavProps(');
    const start = sourceBetween(soc, "if (action === 'start') {", "if (action === 'approve') {");
    assert.match(start, /title: 'Start governed traffic'/);
    assert.match(start, /confirmTone: 'danger' as const/);
    assert.match(start, /confirmLabel: 'Start traffic'/);
    assert.match(start, /requireTypedId: entityId/);
    assert.match(start, /Governed adapter traffic will begin against these domains\./);
    const approve = sourceBetween(soc, "if (action === 'approve') {", "if (action === 'schedule') {");
    assert.match(approve, /All required authorization artifacts and provider approvals are accepted\./);
    assert.match(approve, /confirmTone: 'default' as const/);
  });

  it('gates SOC Start on an open scheduled window, two distinct approvers and a clear kill switch', () => {
    const soc = sourceBetween(source, 'function SocRequestDetailView(', 'function detailRowNavProps(');
    assert.match(soc, /label: 'Inside scheduled safe window',\n      pass: windowState === 'open'/);
    assert.match(soc, /Window ended \$\{formatTimestamp\(windowEnd\)\}: reschedule required/);
    assert.match(soc, /label: `Two SOC approvals recorded \(\$\{Math\.min\(approverCount, 2\)\}\/2\)`, pass: approverCount >= 2/);
    assert.match(soc, /label: 'Tenant kill switch clear'/);
    assert.match(soc, /disabled=\{busy !== '' \|\| !preflightReady\}/);
    assert.match(soc, /<CardTitle>Request gates<\/CardTitle>/);
    assert.doesNotMatch(soc, /Confirmed safe window|Safe window confirmed|Go \/ No-Go/);
    assert.match(source, /Start stays disabled until every request gate passes\./);
  });

  it('keeps one always-visible Stop control and polls adapter status without blocking it', () => {
    const soc = sourceBetween(source, 'function SocRequestDetailView(', 'function detailRowNavProps(');
    const banner = sourceBetween(soc, "{state === 'running' ? (\n        <div className=\"form-banner error stack-tight\"", '<div className="kpi-row"');
    assert.match(banner, /LIVE · Governed high-scale traffic is running/);
    assert.match(banner, /onClick=\{\(\) => void socAction\('stop'\)\}>Stop now<\/Button>/);
    assert.equal((soc.match(/socAction\('stop'\)/g) ?? []).length, 1);
    const poll = sourceBetween(soc, "if (!isSoc || !entityId || state !== 'running') return undefined;", 'if (!isSoc) {');
    assert.doesNotMatch(poll, /setBusy/);
    assert.match(poll, /window\.clearInterval\(timer\)/);
    assert.ok(soc.indexOf('data-testid="soc-live-banner"') < soc.indexOf('<Tabs value={tab}'), 'the live banner renders above the tabs');
  });

  it('re-reads the SOC request after every lifecycle action instead of rebuilding it from the POST body', () => {
    assert.match(source, /: route === 'queue-detail'\n            \? highScaleDetail\.reload/);
    assert.equal((sourceBetween(source, "if (route === 'queue-detail') {\n    const staffSocWorkspace", "if (!entityId) {\n    const noSelectionByRoute").match(/onRefresh=\{refreshWithEntity\}/g) ?? []).length, 2);
    const listBacked = sourceBetween(source, 'function useListBackedDetail<', 'function formatRunDuration(');
    assert.match(listBacked, /\[config, session, listPath, enabled, entityId, staffSoc, tenantId, reloadTick\]/);
    assert.match(listBacked, /return \{ detail, error, loading, reload \};/);
  });

  it('never invents an active lifecycle for a tenant without an account record, and suspends only with a typed ID', () => {
    const tenant = sourceBetween(source, 'function TenantDetailView(', 'function EvidenceDetailView(');
    assert.match(tenant, /const lifecycleRecorded = Boolean\(getString\(account, \['lifecycle_state'\], ''\)\);/);
    assert.match(tenant, /lifecycleRecorded \? formatStatusLabel\(lifecycleState\) : 'Not recorded'/);
    assert.match(tenant, /delta=\{lifecycleRecorded \? 'Staff account state' : 'No account record'\}/);
    assert.match(tenant, /requireTypedId: suspending \? entityId : undefined/);
    assert.match(tenant, /reason: \{ label: 'Reason \(recorded in the staff audit log\)', required: true \}/);
    assert.doesNotMatch(tenant, /Disabled from tenant detail|from tenant detail\./);
  });

  it('tells SOC what a rejected artifact needs and never accepts with a canned note', () => {
    const soc = sourceBetween(source, 'function SocRequestDetailView(', 'function detailRowNavProps(');
    assert.match(soc, /reason: \{ label: 'Reason shown to the customer', required: true \}/);
    assert.match(soc, /\{ status, notes: null \}/);
    assert.doesNotMatch(soc, /SOC rejected via request detail|SOC accepted via request detail/);
    assert.match(soc, /Execution still requires every required artifact to be accepted/);
  });
});

