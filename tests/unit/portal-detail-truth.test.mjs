import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const source = readFileSync('apps/web/react/src/pages/detail-pages.tsx', 'utf8');
const functionalSurfaces = readFileSync('apps/web/react/src/pages/functional-surfaces.tsx', 'utf8');
const targetGroupDetail = readFileSync('apps/web/react/src/pages/target-group-detail-view.tsx', 'utf8');

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
    for (const verdict of ['edge_exposed', 'bypassable', 'penetrated', 'exposed', 'unprotected']) {
      assert.ok(source.includes(`'${verdict}'`), verdict);
    }
  });

  it('omits unsupported agent aliases from global and current-group run tables', () => {
    const globalRunColumns = sourceBetween(
      functionalSurfaces,
      "if (route === 'runs')",
      'const canOpenVectorLibrary =',
    );
    const currentGroupRunColumns = sourceBetween(
      targetGroupDetail,
      'const runColumns:',
      'const dnsHistoryColumns:',
    );

    for (const tableSource of [globalRunColumns, currentGroupRunColumns]) {
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
});
