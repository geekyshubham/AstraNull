import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { catalogRuleCoverage } from '../../src/contracts/ruleCoverage.mjs';
import { exposedVerdictLabel, networkOutcomeSentence, probeEvidenceModel, probeResultEvents } from '../../apps/web/react/src/lib/probe-evidence.mjs';
import {
  ASSURANCE_META,
  coverageStatusCounts,
  filterCoverageByLayer,
  normalizeRuleCoverage,
  sortCoverageForAttention,
} from '../../apps/web/react/src/lib/rule-coverage.mjs';
import { firewallItemStatus, firewallReasonLabel } from '../../apps/web/react/src/components/targets/entry-paths/presenter.mjs';
import { FINDING_CLOSURE_STATUSES, FINDING_STATUS_GROUPS, FINDING_STATUS_LABELS, FINDING_STATUSES, findingStatusTransitions } from '../../apps/web/react/src/lib/findings-query.mjs';

describe('probe evidence view model', () => {
  it('shows per-placement outcomes, source penalty and grading versions for a WAF marker result', () => {
    const model = probeEvidenceModel({
      assurance_scope: 'managed_rule_marker',
      enforcement: 'partial',
      source_penalized: true,
      trailing_control: { outcome: 'blocked', status_code: 403 },
      leg_order: ['header', 'query', 'path'],
      cache_buster: true,
      placements: [
        { placement: 'query', outcome: 'blocked', status_code: 403, signature_id: 'cloudflare_1020', cache_status: 'DYNAMIC' },
        { placement: 'path', outcome: 'challenged', status_code: 403, signature_id: null, cache_status: null },
        { placement: 'header', outcome: 'redirected', status_code: 302, location_changed: true },
      ],
      grading_version: 'waf-grading.v2',
      signature_corpus_version: 'waf-signatures.2026-10-13.2',
    });
    assert.deepEqual(model.chips.map((chip) => chip.label), ['Blocked', 'Challenged', 'Redirected', 'Source penalized']);
    assert.equal(model.placements[0].placementLabel, 'Query string');
    assert.equal(model.placements[1].outcomeLabel, 'Challenged');
    assert.equal(model.placements[2].locationChanged, true);
    assert.equal(model.scope.label, 'Managed rule marker');
    assert.match(model.enforcement.text, /Partly enforced/);
    assert.equal(model.trailing.outcomeLabel, 'Blocked');
    assert.deepEqual(model.metaRows.map((row) => row.label), ['Grading', 'Signatures', 'Request order', 'Cache bypass']);
    assert.equal(model.metaRows[2].value, 'Request header → Query string → URL path');
  });

  it('flags a normalization gap from an evasion result', () => {
    const model = probeEvidenceModel({ reference_outcome: 'blocked', transform_outcome: 'allowed', normalization_gap: true, reference_not_enforced: false, transform: 'double_url' });
    assert.equal(model.evasion.normalizationGap, true);
    assert.equal(model.evasion.transform, 'double URL encoding');
    assert.equal(model.evasion.referenceLabel, 'Blocked');
    assert.equal(model.evasion.transformedLabel, 'Allowed');
  });

  it('describes network outcomes in plain words with IPv4/IPv6 parity and perspective', () => {
    const model = probeEvidenceModel({
      protocol: 'tcp', port: 22, address_family: 4, tcp_outcome: 'rejected_icmp',
      icmp: { kind: 'admin_prohibited', errno: 'EHOSTUNREACH' },
      families: { ipv4: { address: '192.0.2.10', tcp_outcome: 'rejected_icmp' }, ipv6: { address: '2001:db8::10', tcp_outcome: 'handshake' } },
      parity: 'mismatch', sample_agreement: 'agree', samples: [{}, {}], peer_is_cdn: false,
      source_perspective: { id: 'eu-west', label: 'EU West' },
    });
    assert.equal(model.network.outcomeLabel, 'Rejected by firewall (ICMP)');
    assert.match(model.network.icmp, /administratively prohibited/);
    assert.equal(model.network.families[1].result.label, 'Handshake completed');
    assert.equal(model.network.parity.label, 'IPv4 and IPv6 differ');
    assert.equal(model.perspective.label, 'EU West');
    assert.equal(networkOutcomeSentence(model.network), 'TCP 22 over IPv4: Rejected by firewall (ICMP) (ICMP administratively prohibited (typically a firewall rule))');
    assert.equal(probeEvidenceModel({ protocol: 'udp', udp_outcome: 'silent' }).network.outcomeLabel, 'No reply');
  });

  it('words an exposed verdict for the control that was tested, never as direct server access', () => {
    assert.equal(exposedVerdictLabel('waf.sqli_managed_marker.safe', 'exposed'), 'The WAF did not stop the test traffic');
    assert.equal(exposedVerdictLabel('nfw.declared_deny_tcp.safe', 'exposed'), 'A declared firewall rule was not enforced');
    assert.equal(exposedVerdictLabel('nfw.origin_lockdown.safe', 'exposed'), 'Your origin answered directly, outside the CDN');
    assert.equal(exposedVerdictLabel('origin.direct_bypass.safe', 'edge_exposed'), '');
    assert.equal(exposedVerdictLabel('waf.sqli_managed_marker.safe', 'protected'), '');
  });

  it('labels a suspected block on an unverified vendor signature, local errors and reflector exposures honestly', () => {
    const suspected = probeEvidenceModel({ inconclusive_reason: 'block_suspected_unverified_signature', matched_vendor: 'ExampleWAF', placements: [{ placement: 'query', outcome: 'inconclusive', status_code: 403, inconclusive_reason: 'block_suspected_unverified_signature', matched_vendor: 'ExampleWAF' }] });
    assert.equal(suspected.inconclusiveReason, 'Block suspected — vendor signature not yet verified (ExampleWAF)');
    assert.equal(suspected.placements[0].reasonLabel, 'Block suspected — vendor signature not yet verified (ExampleWAF)');
    const local = probeEvidenceModel({ protocol: 'tcp', port: 22, tcp_outcome: 'error', local_error: true });
    assert.equal(local.network.outcomeLabel, 'Inconclusive — local probe error');
    assert.ok(local.chips.some((chip) => chip.id === 'inconclusive'));
    const reflector = probeEvidenceModel({ protocol: 'udp', port: 123, udp_outcome: 'validated_reply', exposure_basis: 'validated_reflector_reply' });
    assert.equal(reflector.network.reflectorReachable, true);
    assert.equal(exposedVerdictLabel('reflect.ntp_monlist_exposure.safe', 'exposed'), 'An open reflector is reachable from the internet');
  });

  it('keeps firewall-change items inconclusive for closed ports and local errors', () => {
    assert.equal(firewallItemStatus({ status: 'matched', reasons: ['closed_port_not_control_specific'] }), 'inconclusive');
    assert.equal(firewallItemStatus({ status: 'regression', reasons: [], local_error: true }), 'inconclusive');
    assert.equal(firewallItemStatus({ status: 'regression', reasons: ['other'] }), 'regression');
    assert.match(firewallReasonLabel('closed_port_not_control_specific'), /closed port does not show which control/);
  });

  it('renders nothing for unrelated probes and keeps only signed results', () => {
    assert.equal(probeEvidenceModel({ dnssec_configured: true }), null);
    assert.equal(probeEvidenceModel(null), null);
    const events = probeResultEvents([
      { id: 'a', signal_type: 'probe_activity', producer_kind: 'signed_probe' },
      { id: 'b', signal_type: 'probe_result', producer_kind: 'signed_probe', timestamp: '2030-01-02' },
      { id: 'c', signal_type: 'probe_result', producer_kind: 'customer_declaration' },
    ]);
    assert.deepEqual(events.map((event) => event.id), ['b']);
  });
});

describe('rule coverage view model', () => {
  it('reads the live catalog with honest not-assessable and out-of-scope reasons', () => {
    const model = normalizeRuleCoverage(catalogRuleCoverage());
    const icmp = model.categories.find((category) => category.id === 'icmp_policy');
    assert.equal(icmp.assuranceLabel, 'Not assessable');
    assert.match(icmp.reason, /ICMP/);
    const egress = model.categories.find((category) => category.id === 'egress_filtering');
    assert.equal(egress.assuranceLabel, 'Out of scope');
    assert.match(egress.reason, /inside the network/);
    assert.ok(filterCoverageByLayer(model.categories, 'nfw').every((category) => category.layer === 'nfw'));
    assert.ok(model.categories.every((category) => ASSURANCE_META[category.assurance]), 'every assurance has a legend entry');
  });

  it('shows partial assurance with its reason and keeps machine words out of names', () => {
    const model = normalizeRuleCoverage({ categories: [
      { id: 'request_smuggling', layer: 'waf', name: 'Request smuggling', assurance: 'partial', assurance_reason: 'only custom canary tokens cover this family.', check_ids: ['waf.request_smuggling_marker.safe'], checks: [] },
      { id: 'graphql_api', layer: 'waf', name: 'GraphQL and API schema', assurance: 'observation', checks: [{ check_id: 'l7.api_surface_scan.safe', name: 'API Surface Scan (Safe)', assurance: 'observation' }] },
    ] });
    assert.equal(model.categories[0].assuranceLabel, 'Partial');
    assert.equal(model.categories[0].assuranceReason, 'Only custom canary tokens cover this family.');
    assert.equal(model.categories[0].reason, '', 'a partial reason never replaces the next step');
    assert.equal(model.categories[1].name, 'GraphQL and web service schema');
    assert.equal(model.categories[1].checks[0].name, 'Responses from common API paths');
  });

  it('turns missing declarations into CTAs and orders failures first for a target', () => {
    const model = normalizeRuleCoverage({
      version: 'rule-coverage.v1',
      target_id: 'tgt_demo',
      freshness_policy: { max_age_ms: 7 * 86_400_000 },
      categories: [
        { id: 'sqli', layer: 'waf', name: 'SQL injection', assurance: 'verdict', status: 'covered_pass', checks: [{ check_id: 'waf.sqli_managed_marker.safe', name: 'SQLi', status: 'covered_pass', assurance: 'verdict' }] },
        { id: 'inbound_tcp_deny', layer: 'nfw', name: 'Inbound TCP', assurance: 'violation_only', status: 'needs_declaration', missing_declarations: ['network_policy'], checks: [] },
        { id: 'xss', layer: 'waf', name: 'XSS', assurance: 'verdict', status: 'covered_fail', checks: [] },
        { id: 'allowlists_geo', layer: 'nfw', name: 'Allowlists', assurance: 'violation_only', status: 'not_run', not_runnable_reason: 'two_perspectives_required', checks: [] },
      ],
    });
    assert.equal(model.freshnessDays, 7);
    const tcp = model.categories.find((category) => category.id === 'inbound_tcp_deny');
    assert.equal(tcp.statusLabel, 'Set blocked ports');
    assert.equal(tcp.ctas[0].cta, 'Set blocked ports');
    assert.equal(tcp.ctas[0].section, 'network');
    assert.match(model.categories.find((category) => category.id === 'allowlists_geo').reason, /two registered probe source locations/);
    assert.deepEqual(sortCoverageForAttention(model.categories).map((category) => category.id), ['xss', 'inbound_tcp_deny', 'sqli', 'allowlists_geo']);
    assert.equal(coverageStatusCounts(model.categories).covered_fail, 1);
  });
});

describe('finding lifecycle labels', () => {
  it('adds fix verified as a closed status that can be reopened', () => {
    assert.ok(FINDING_STATUSES.includes('fix_verified'));
    assert.equal(FINDING_STATUS_LABELS.fix_verified, 'Fix verified');
    assert.ok(FINDING_CLOSURE_STATUSES.includes('fix_verified'));
    assert.ok(FINDING_STATUS_GROUPS.find((group) => group.id === 'closed').statuses.includes('fix_verified'));
    assert.ok(!FINDING_STATUS_GROUPS.find((group) => group.id === 'active').statuses.includes('accepted_risk'), 'accepted risk is never active risk');
    assert.deepEqual(findingStatusTransitions('fix_verified').map((entry) => entry.status), ['open', 'in_progress']);
  });
});
