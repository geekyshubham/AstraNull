import '../helpers/dev-data-dir.mjs';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { listChecks } from '../../src/services/testRuns.mjs';
import { rederiveVerdict } from '../../src/lib/verdictReplay.mjs';
import {
  classifyTcpErrno,
  classifyUdpErrno,
  REJECT_ICMP_MIN_ELAPSED_MS,
} from '../../src/lib/networkProbeOutcomes.mjs';
import { classifyFirewallChangeItem } from '../../src/lib/firewallChangeAcceptance.mjs';
import { normalizeFirewallExpectation } from '../../src/contracts/protectionValidation.mjs';
import {
  getCheckById,
  targetInputRefusal,
  checkAdditionalInputReason,
} from '../../src/contracts/checks.mjs';
import { catalogRuleCoverage } from '../../src/contracts/ruleCoverage.mjs';
import {
  normalizeControlDeclarations,
  controlDeclarationsFromTarget,
} from '../../src/contracts/controlDeclarations.mjs';
import { assertProbeDestinationAllowed } from '../../src/lib/probeEndpoint.mjs';
import {
  createPostgresWafOrchestratorServices,
  WAF_ORCHESTRATOR_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/wafOrchestratorServiceAdapters.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

describe('R3b Item 1 (N1): Worker metadata stripping and declarations precedence', () => {
  it('worker metadata containing declarations on a target with none stored does not give exposed', () => {
    freshStore();
    const store = getStore();
    const target = store.targets.find((t) => t.id === 'tgt_1');
    target.metadata = {};

    const verdict = correlateExternalOnlyVerdict({
      probeKind: 'tcp_connect',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: {
        safety_attestation: { probe_requests_sent: 1 },
        tcp_outcome: 'handshake',
        port: 22,
        declarations: {
          network_policy: [{ protocol: 'tcp', port: 22, action: 'deny' }],
        },
        expected_behavior: 'must_block_before_origin',
        declared_limit: 1,
      },
      declarations: controlDeclarationsFromTarget(target),
    });
    assert.notEqual(verdict?.verdict, 'exposed');
  });

  it('rederiveVerdict strips worker declarations, expected_behavior, and declared_limit', () => {
    const evidenceRecord = {
      external_result: 'connected',
      probe_kind: 'tcp_connect',
      probe_io_observed: true,
      metadata: {
        tcp_outcome: 'handshake',
        port: 22,
        declarations: {
          network_policy: [{ protocol: 'tcp', port: 22, action: 'deny' }],
        },
        expected_behavior: 'must_block_before_origin',
        declared_limit: 5,
      },
      declarations: null,
    };
    const replayed = rederiveVerdict(evidenceRecord);
    assert.notEqual(replayed?.verdict, 'exposed');
  });
});

describe('R3b Item 2 (N2): Connection limit rule sourcing', () => {
  it('connection_limit_probe is inconclusive when declarations have no connection_limits rule', () => {
    const verdict = correlateExternalOnlyVerdict({
      probeKind: 'connection_limit_probe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: {
        port: 443,
        accepted_count: 50,
        declared_limit: 5,
      },
      declarations: {},
    });
    assert.equal(verdict.verdict, 'inconclusive');
    assert.match(verdict.explanation, /No declared connection limit configured/);
  });

  it('connection_limit_probe flags exposed when admitted connections exceed declared limit', () => {
    const verdict = correlateExternalOnlyVerdict({
      probeKind: 'connection_limit_probe',
      externalResult: 'connected',
      probeIoObserved: true,
      probeMetadata: {
        port: 443,
        accepted_count: 15,
      },
      declarations: {
        connection_limits: [
          { protocol: 'tcp', port: 443, max_connections_per_source: 10 },
        ],
      },
    });
    assert.equal(verdict.verdict, 'exposed');
    assert.match(verdict.explanation, /accepted 15 connections above the declared limit of 10/);
  });
});

describe('R3b Item 3 (N3): Network probe outcome classification and firewall change acceptance', () => {
  it('classifies ENETUNREACH and EHOSTUNREACH as rejected_icmp, while EACCES and EPERM are local_error', () => {
    assert.equal(classifyTcpErrno('ENETUNREACH').tcp_outcome, 'rejected_icmp');
    assert.equal(classifyTcpErrno('EHOSTUNREACH').tcp_outcome, 'rejected_icmp');
    assert.equal(classifyTcpErrno('EACCES').local_error, true);
    assert.equal(classifyTcpErrno('EPERM').local_error, true);

    assert.equal(classifyUdpErrno('ENETUNREACH').udp_outcome, 'rejected_icmp');
    assert.equal(classifyUdpErrno('EHOSTUNREACH').udp_outcome, 'rejected_icmp');
    assert.equal(classifyUdpErrno('EACCES').local_error, true);
    assert.equal(classifyUdpErrno('EPERM').local_error, true);
  });

  it('immediate ENETUNREACH is not deny evidence (marked local_error / path_not_proven)', () => {
    const exp = {
      ...normalizeFirewallExpectation({
        destination_target_id: 'tgt_1',
        protocol: 'tcp',
        port: 8080,
        expected: 'deny',
        source_perspective: 'p1',
        change_id: 'CHG-1',
      }, { tenantId: 'ten_demo' }),
      id: 'fwx_1',
      status: 'active',
    };
    const pre = [
      { observation_class: 'reachable_transport_only', source_perspective: 'p1', address_family: 'ipv4' },
    ];
    const post = [
      {
        observation_class: 'explicit_denial_observed',
        denial_basis: 'rejected_icmp',
        elapsed_ms: REJECT_ICMP_MIN_ELAPSED_MS - 1,
        source_perspective: 'p1',
        address_family: 'ipv4',
      },
    ];

    const classified = classifyFirewallChangeItem({
      expectation: exp,
      baselineObservations: pre,
      candidateObservations: post,
      compatibility: { comparable: true, reasons: [] },
    });
    assert.equal(classified.status, 'inconclusive');
    assert.equal(classified.local_error, true);
    assert.ok(classified.reasons.includes('path_not_proven'));
  });

  it('slow reject without a proven path is path_not_proven', () => {
    const exp = {
      ...normalizeFirewallExpectation({
        destination_target_id: 'tgt_1',
        protocol: 'tcp',
        port: 8080,
        expected: 'deny',
        source_perspective: 'p1',
        change_id: 'CHG-2',
      }, { tenantId: 'ten_demo' }),
      id: 'fwx_2',
      status: 'active',
    };
    const pre = [
      { observation_class: 'no_response', source_perspective: 'p1', address_family: 'ipv4' },
    ];
    const post = [
      {
        observation_class: 'explicit_denial_observed',
        denial_basis: 'rejected_icmp',
        elapsed_ms: REJECT_ICMP_MIN_ELAPSED_MS + 5,
        source_perspective: 'p1',
        address_family: 'ipv4',
      },
    ];

    const classified = classifyFirewallChangeItem({
      expectation: exp,
      baselineObservations: pre,
      candidateObservations: post,
      compatibility: { comparable: true, reasons: [] },
    });
    assert.equal(classified.status, 'inconclusive');
    assert.equal(classified.local_error, true);
    assert.ok(classified.reasons.includes('path_not_proven'));
  });

  it('slow reject with a proven path counts as deny evidence', () => {
    const exp = {
      ...normalizeFirewallExpectation({
        destination_target_id: 'tgt_1',
        protocol: 'tcp',
        port: 8080,
        expected: 'deny',
        source_perspective: 'p1',
        change_id: 'CHG-3',
      }, { tenantId: 'ten_demo' }),
      id: 'fwx_3',
      status: 'active',
    };
    const pre = [
      { observation_class: 'reachable_transport_only', source_perspective: 'p1', address_family: 'ipv4' },
      { observation_class: 'reachable_transport_only', source_perspective: 'p1', address_family: 'ipv4' },
    ];
    const post = [
      {
        observation_class: 'explicit_denial_observed',
        denial_basis: 'rejected_icmp',
        elapsed_ms: REJECT_ICMP_MIN_ELAPSED_MS + 5,
        source_perspective: 'p1',
        address_family: 'ipv4',
      },
      {
        observation_class: 'explicit_denial_observed',
        denial_basis: 'rejected_icmp',
        elapsed_ms: REJECT_ICMP_MIN_ELAPSED_MS + 6,
        source_perspective: 'p1',
        address_family: 'ipv4',
      },
    ];

    const classified = classifyFirewallChangeItem({
      expectation: exp,
      baselineObservations: pre,
      candidateObservations: post,
      compatibility: { comparable: true, reasons: [] },
    });
    assert.equal(classified.status, 'improvement');
  });
});

describe('R3b Item 4 (N4): Target dependent requirements and refusal codes', () => {
  const checksToTest = [
    {
      checkId: 'nfw.declared_deny_tcp.safe',
      expectedRefusal: 'declared_tcp_deny_required',
      validDeclarations: {
        network_policy: [{ protocol: 'tcp', port: 22, action: 'deny' }],
      },
    },
    {
      checkId: 'nfw.declared_deny_udp.safe',
      expectedRefusal: 'declared_udp_deny_required',
      validDeclarations: {
        network_policy: [{ protocol: 'udp', port: 53, action: 'deny' }],
      },
    },
    {
      checkId: 'nfw.connection_limit.safe',
      expectedRefusal: 'declared_connection_limit_required',
      validDeclarations: {
        connection_limits: [{ protocol: 'tcp', port: 443, max_connections_per_source: 10 }],
      },
    },
    {
      checkId: 'waf.rate_limit_canary.validation',
      expectedRefusal: 'declared_rate_limit_canary_required',
      validDeclarations: {
        waf: { rate_limit_canary: { path: '/canary', method: 'GET', threshold: 5, window_seconds: 60 } },
      },
    },
    {
      checkId: 'nfw.origin_lockdown.safe',
      expectedRefusal: 'declared_origin_lockdown_required',
      validDeclarations: {
        origin: { lockdown_expected: true },
      },
      targetExtra: {
        tenant_id: 'ten_cust',
        kind: 'fqdn',
        value: 'app.example.com',
        origin_bindings: {
          bindings: [{
            id: 'ob_1',
            tenant_id: 'ten_cust',
            status: 'active',
            protected_target_id: 'tgt_sample',
            origin_target_id: 'tgt_origin',
            host: 'app.example.com',
            sni: 'app.example.com',
            port: null,
            path: null,
          }],
          records: {
            targets: [
              { id: 'tgt_sample', tenant_id: 'ten_cust', kind: 'fqdn', value: 'app.example.com' },
              { id: 'tgt_origin', tenant_id: 'ten_cust', kind: 'ip', value: '203.0.113.10' },
            ],
            targetVerifications: [
              { id: 'v_origin', tenant_id: 'ten_cust', target_id: 'tgt_origin', state: 'dns_verified', transitioned_at: '2026-10-01T00:00:00.000Z' },
              { id: 'v_protected', tenant_id: 'ten_cust', target_id: 'tgt_sample', state: 'dns_verified', transitioned_at: '2026-10-01T00:00:00.000Z' },
            ],
          },
        },
      },
    },
    {
      checkId: 'nfw.perspective_allowlist.safe',
      expectedRefusal: 'declared_perspectives_required',
      validDeclarations: {
        perspectives: { allowlisted_perspective_ids: ['primary'], denied_perspective_ids: ['secondary'] },
      },
    },
  ];

  const envTwoPerspectives = { ASTRANULL_PROBE_PERSPECTIVES: JSON.stringify([{ id: 'p1', label: 'P1' }, { id: 'p2', label: 'P2' }]) };

  for (const { checkId, validDeclarations, targetExtra } of checksToTest) {
    it(`${checkId} runs without input and still accepts declarations`, () => {
      const check = getCheckById(checkId);
      assert.ok(check, `Check ${checkId} must exist`);

      const targetEmpty = { id: 'tgt_sample', metadata: {} };
      assert.equal(targetInputRefusal(check, targetEmpty), null);
      assert.equal(checkAdditionalInputReason(check, { target: targetEmpty, env: envTwoPerspectives }), null);

      const targetWithDeclarations = {
        id: 'tgt_sample',
        metadata: {
          control_declarations: validDeclarations,
        },
        ...(targetExtra ?? {}),
      };
      assert.equal(targetInputRefusal(check, targetWithDeclarations), null);
    });
  }

  it('listChecks reports no additional input requirement', () => {
    freshStore();
    const store = getStore();
    const target = store.targets.find((t) => t.id === 'tgt_1');
    target.metadata = {};

    const items = listChecks({ scope: 'all', target });
    assert.ok(Array.isArray(items));
    const connCheck = items.find((c) => c.check_id === 'nfw.connection_limit.safe');
    assert.ok(connCheck);
    assert.equal(connCheck.requires_additional_input, false);
    assert.equal(connCheck.additional_input_reason, null);

    const tcpCheck = items.find((c) => c.check_id === 'nfw.declared_deny_tcp.safe');
    assert.ok(tcpCheck);
    assert.equal(tcpCheck.requires_additional_input, false);
    assert.equal(tcpCheck.additional_input_reason, null);
  });
});

describe('R3b Item 5 (N6): Rule coverage for rfi and cve_virtual_patching', () => {
  it('rfi and cve_virtual_patching are marked missing with clear safety rationale', () => {
    const coverage = catalogRuleCoverage();
    const rfi = coverage.categories.find((c) => c.id === 'rfi');
    const cve = coverage.categories.find((c) => c.id === 'cve_virtual_patching');

    assert.equal(rfi.assurance, 'missing');
    assert.match(rfi.assurance_reason, /Remote-file-inclusion and CVE exploit markers/);

    assert.equal(cve.assurance, 'missing');
    assert.match(cve.assurance_reason, /Remote-file-inclusion and CVE exploit markers/);
  });
});

describe('R3b Item 6 (N7): Postgres preflight SOC-gated refusal and audit', () => {
  it('runs SOC-gated scenarios without a 403 soc_gated_check refusal', async () => {
    const ctx = { tenantId: 'ten_soc', userId: 'usr_soc', role: 'admin' };
    const fixed = new Date('2026-07-03T12:00:00.000Z');
    const plan = {
      id: 'plan_soc_gate',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'scheduled',
      scenarios: ['rce_marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    };
    const wafOrchestrator = {};
    for (const method of WAF_ORCHESTRATOR_REPOSITORY_METHODS) {
      wafOrchestrator[method] = async () => null;
    }
    wafOrchestrator.getValidationPlan = async () => plan;
    wafOrchestrator.claimValidationPlanExecution = async () => plan;
    wafOrchestrator.stageValidationPlanDelegation = async () => ({ delegated_jobs: [] });
    wafOrchestrator.finishValidationPlanExecution = async () => ({ ...plan, state: 'completed' });

    const auditEvents = [];
    const repositories = {
      wafOrchestrator,
      coreCatalog: {
        getTargetGroup: async () => ({
          id: 'tg_1',
          targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
        }),
      },
      wafPosture: {
        listWafAssets: async () => [
          { id: 'waf_asset_1', target_group_id: 'tg_1', target_id: 'tgt_1' },
        ],
        patchWafDriftEvent: async () => ({}),
      },
      targets: {
        listTargets: async () => [{ id: 'tgt_1' }],
      },
      audit: {
        appendAuditEvent: async (entry) => {
          auditEvents.push(entry);
        },
      },
    };

    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      newId: () => 'id_gen',
      testRuns: {
        startTestRun: async () => ({ run: { id: 'run_1' }, probe_job: { id: 'job_1' } }),
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_soc_gate', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'completed');

    const blockedAudit = auditEvents.find((e) => e.action === 'waf.validation_plan.blocked_soc_gated');
    assert.equal(blockedAudit, undefined);
  });
});

describe('R3b Item 7 (N8): Destination guard denylist table', () => {
  const deniedAddresses = [
    { ip: '100.64.0.1', desc: 'CGNAT lower bound' },
    { ip: '100.100.100.200', desc: 'CGNAT interior address' },
    { ip: '100.127.255.254', desc: 'CGNAT upper bound' },
    { ip: '224.0.0.1', desc: 'IPv4 multicast lower' },
    { ip: '239.255.255.250', desc: 'IPv4 multicast upper' },
    { ip: '240.0.0.1', desc: 'IPv4 reserved' },
    { ip: '254.255.255.254', desc: 'IPv4 reserved' },
    { ip: '255.255.255.255', desc: 'IPv4 broadcast' },
    { ip: 'ff00::1', desc: 'IPv6 multicast' },
    { ip: 'ff02::1', desc: 'IPv6 multicast link-local' },
    { ip: 'fec0::1', desc: 'IPv6 site-local' },
    { ip: '2001::1', desc: 'IPv6 Teredo 2001::/32' },
    { ip: '2001:0000:4136:e378:8000:63bf:3fff:fdd2', desc: 'IPv6 Teredo full' },
    { ip: '2002::1', desc: 'IPv6 6to4 2002::/16' },
    { ip: '2002:c0a8:1::1', desc: 'IPv6 6to4 with embedded' },
    { ip: '64:ff9b::1', desc: 'NAT64 prefix 64:ff9b::/96' },
    { ip: '64:ff9b::a9fe:a9fe', desc: 'NAT64 prefix with embedded cloud metadata' },
    { ip: '64:ff9b:1::1', desc: 'Local NAT64 64:ff9b:1::/48' },
    { ip: '::ffff:100.100.100.200', desc: 'IPv4-mapped CGNAT' },
    { ip: '::ffff:224.0.0.1', desc: 'IPv4-mapped multicast' },
    { ip: '::ffff:255.255.255.255', desc: 'IPv4-mapped broadcast' },
    { ip: '::100.100.100.200', desc: 'IPv4-compatible CGNAT' },
    { ip: '::192.168.1.1', desc: 'IPv4-compatible RFC1918' },
    { ip: '0.0.0.1', desc: '0.0.0.0/8 source/this-network' },
    { ip: '::ffff:0:127.0.0.1', desc: 'SIIT ::ffff:0:0:0/96 embedded loopback' },
    { ip: '::ffff:0:169.254.169.254', desc: 'SIIT ::ffff:0:0:0/96 embedded cloud metadata' },
    { ip: '::ffff:0:10.0.0.1', desc: 'SIIT ::ffff:0:0:0/96 embedded RFC1918' },
  ];

  for (const { ip, desc } of deniedAddresses) {
    it(`denies ${ip} (${desc})`, () => {
      const result = assertProbeDestinationAllowed(ip);
      assert.equal(result.ok, false, `Expected ${ip} (${desc}) to be denied`);
    });
  }

  it('allows valid routable IPv4 and IPv6 addresses', () => {
    assert.equal(assertProbeDestinationAllowed('93.184.216.34').ok, true);
    assert.equal(assertProbeDestinationAllowed('2606:2800:220:1:248:1893:25c8:1946').ok, true);
  });
});

describe('R3b Item 8 (N10): Exact canary sink host requirement', () => {
  it('accepts canary sink when host matches target host exactly', () => {
    const normalized = normalizeControlDeclarations(
      { canary_sink: { url: 'https://example.com/sink' } },
      { target: { kind: 'fqdn', value: 'example.com' } },
    );
    assert.equal(normalized.canary_sink.url, 'https://example.com/sink');
  });

  it('rejects canary sink when host is a subdomain of the target host', () => {
    assert.throws(
      () =>
        normalizeControlDeclarations(
          { canary_sink: { url: 'https://sub.example.com/sink' } },
          { target: { kind: 'fqdn', value: 'example.com' } },
        ),
      (err) => err.message.includes('canary_sink.url host must equal the target host'),
    );
  });

  it('rejects canary sink when host is a different domain', () => {
    assert.throws(
      () =>
        normalizeControlDeclarations(
          { canary_sink: { url: 'https://different.org/sink' } },
          { target: { kind: 'fqdn', value: 'example.com' } },
        ),
      (err) => err.message.includes('canary_sink.url host must equal the target host'),
    );
  });
});
