import '../helpers/dev-data-dir.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { getCheckById, targetInputRefusal, additionalInputRefusal } from '../../src/contracts/checks.mjs';
import { sanitizeProbeMetadata } from '../../workers/probe-worker.mjs';
import { sanitizeWorkerProbeMetadata } from '../../src/lib/probeResultValidation.mjs';
import { runWafClassMarkerProbe } from '../../src/lib/vectorProbes/wafClassProbes.mjs';
import { buildVerdictReplay, rederiveVerdict } from '../../src/lib/verdictReplay.mjs';
import { correlateExternalOnlyVerdict } from '../../src/services/correlation.mjs';
import { runRateLimitCanaryProbe } from '../../src/lib/vectorProbes/rateLimitCanaryProbes.mjs';
import { normalizeControlDeclarations } from '../../src/contracts/controlDeclarations.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { patchFinding, getFinding } from '../../src/services/findings.mjs';
import { peerIsCdn } from '../../src/lib/networkProbeOutcomes.mjs';
import { targetRuleCoverage } from '../../src/services/ruleCoverage.mjs';

describe('Ticket R5 — Verification defects', () => {
  describe('Item 1: Replay must never invent a verdict change', () => {
    const check = getCheckById('waf.sqli_managed_marker.safe');

    function makeFetch(respond) {
      return async (url, init) => {
        const u = new URL(String(url));
        const marker = decodeURIComponent(u.href).toLowerCase().includes('astranull')
          || Boolean(init?.headers?.['x-astranull-marker'])
          || String(init?.headers?.['user-agent'] ?? '').toLowerCase().includes('astranull');
        return respond(marker, u, init);
      };
    }

    async function runReplayScenario(respond, { declared = null, declarations = null } = {}) {
      const raw = await runWafClassMarkerProbe({
        url: 'https://app.example.com/app',
        marker_class: check.probe_profile.marker_class,
        profile: check.probe_profile,
        fetchFn: makeFetch(respond),
        declared_block_signature: declared,
        rng: () => 0.3,
      });
      const s1 = sanitizeProbeMetadata(raw);
      const s2 = sanitizeWorkerProbeMetadata(s1);
      const md = s2?.metadata ?? s2;
      const live = correlateExternalOnlyVerdict({
        externalResult: null,
        expectedBehavior: null,
        probeKind: check.probe_profile.kind,
        probeIoObserved: true,
        probeMetadata: s1,
        declarations,
        checkId: check.check_id,
      });
      const rep = buildVerdictReplay({
        run: { id: 'run_1', check_id: check.check_id },
        storedVerdict: { verdict: live.verdict },
        probeEvent: { metadata: md },
        declarations,
      });
      return { raw, live, rep, md };
    }

    it('(a) declared block header outside header allowlist keeps stored verdict with changed: false', async () => {
      const declCustom = { header_name: 'x-acme-blocked', header_value: 'yes', status_codes: [403] };
      const { rep, live } = await runReplayScenario(
        (m) => (m ? new Response('blocked', { status: 403, headers: { 'x-acme-blocked': 'yes' } }) : new Response('ok', { status: 200 })),
        { declared: declCustom, declarations: { waf: { block_signature: declCustom } } },
      );
      assert.equal(live.verdict, 'protected');
      assert.equal(rep.regraded, true);
      assert.equal(rep.rederived.verdict, 'protected');
      assert.equal(rep.changed, false);
    });

    it('(b) body block page keeps stored verdict with changed: false', async () => {
      const { rep, live } = await runReplayScenario(
        (m) => (m
          ? new Response('<title>Attention Required! | Cloudflare</title> cf-error-details', {
              status: 403,
              headers: { server: 'cloudflare', 'cf-ray': 'abc-LHR', 'content-type': 'text/html' },
            })
          : new Response('ok', { status: 200, headers: { server: 'cloudflare', 'cf-ray': 'abc-LHR' } })),
      );
      assert.equal(live.verdict, 'protected');
      assert.equal(rep.regraded, true);
      assert.equal(rep.rederived.verdict, 'protected');
      assert.equal(rep.changed, false);
    });

    it('(c) redirected marker leg keeps stored verdict with changed: false', async () => {
      let count = 0;
      const { rep, live } = await runReplayScenario(
        (m) => {
          if (!m) return new Response('ok', { status: 200 });
          count += 1;
          return count === 1
            ? new Response('', { status: 302, headers: { location: 'https://app.example.com/denied' } })
            : new Response('blocked', { status: 403, headers: { 'x-waf-block': '1' } });
        },
      );
      assert.equal(live.verdict, 'protected');
      assert.equal(rep.regraded, true);
      assert.equal(rep.rederived.verdict, 'protected');
      assert.equal(rep.changed, false);
    });

    it('(d) multi-path class-marker run grades each path against its own baseline', async () => {
      const multiCheck = {
        ...check,
        probe_profile: {
          ...check.probe_profile,
          paths: ['/app/api', '/app/checkout'],
        },
      };
      const raw = await runWafClassMarkerProbe({
        url: 'https://app.example.com/app',
        marker_class: multiCheck.probe_profile.marker_class,
        profile: multiCheck.probe_profile,
        fetchFn: makeFetch((m, u) => {
          if (!m) {
            const status = u.pathname.includes('/checkout') ? 201 : 200;
            return new Response('baseline', { status });
          }
          return new Response('blocked', { status: 403, headers: { 'x-waf-block': '1' } });
        }),
        rng: () => 0.3,
      });
      const s1 = sanitizeProbeMetadata(raw);
      const s2 = sanitizeWorkerProbeMetadata(s1);
      const md = s2?.metadata ?? s2;
      const live = correlateExternalOnlyVerdict({
        externalResult: null,
        expectedBehavior: null,
        probeKind: multiCheck.probe_profile.kind,
        probeIoObserved: true,
        probeMetadata: s1,
        declarations: null,
        checkId: multiCheck.check_id,
      });
      const rep = buildVerdictReplay({
        run: { id: 'run_multi', check_id: multiCheck.check_id },
        storedVerdict: { verdict: live.verdict },
        probeEvent: { metadata: md },
        declarations: null,
      });
      assert.equal(live.verdict, 'protected');
      assert.equal(rep.regraded, true);
      assert.equal(rep.rederived.verdict, 'protected');
      assert.equal(rep.changed, false);
    });

    it('(e) old feature without new fields returns regraded: false, reason: insufficient_features', () => {
      const oldFeatures = [
        { placement: 'baseline', status_code: 200, header_subset: {}, body_length_bucket: 'lt_8kb' },
        { placement: 'path', status_code: 403, header_subset: {}, body_length_bucket: 'lt_8kb', signature_id: 'block_sig_cloudflare_attention' },
      ];
      const rep = buildVerdictReplay({
        run: { id: 'run_old', check_id: check.check_id },
        storedVerdict: { verdict: 'protected' },
        probeEvent: {
          metadata: {
            baseline: { status_code: 200, header_subset: {} },
            response_features: oldFeatures,
            placements: [{ placement: 'path', status_code: 403, outcome: 'blocked' }],
          },
        },
        declarations: null,
      });
      assert.equal(rep.regraded, false);
      assert.equal(rep.regrade_unavailable_reason, 'insufficient_features');
      assert.equal(rep.changed, false);
    });
  });

  describe('Item 2: Rate-limit 503/404 must not count as exposed', () => {
    const decls = normalizeControlDeclarations({
      waf: { rate_limit_canary: { path: '/api/canary', method: 'GET', threshold: 5, window_seconds: 10 } },
    });
    const canary = decls.waf.rate_limit_canary;
    const checkId = 'waf.rate_limit_canary.safe';

    const corr = (md) => correlateExternalOnlyVerdict({
      externalResult: 'connected',
      expectedBehavior: null,
      probeKind: 'rate_limit_canary_probe',
      probeIoObserved: true,
      probeMetadata: sanitizeWorkerProbeMetadata(md),
      declarations: decls,
      checkId,
    });

    it('all 503 responses result in inconclusive with unattributed_errors', async () => {
      const out = await runRateLimitCanaryProbe({
        url: 'https://app.example.com/',
        canary,
        rate_limit_canary: canary,
        declarations: decls,
        fetchFn: async () => new Response('error', { status: 503 }),
      });
      const md = sanitizeWorkerProbeMetadata(sanitizeProbeMetadata(out));
      const res = corr(md);
      assert.equal(res.verdict, 'inconclusive');
      assert.match(res.explanation, /unattributed_errors/);
    });

    it('all 404 responses result in inconclusive with unattributed_errors', async () => {
      const out = await runRateLimitCanaryProbe({
        url: 'https://app.example.com/',
        canary,
        rate_limit_canary: canary,
        declarations: decls,
        fetchFn: async () => new Response('not found', { status: 404 }),
      });
      const md = sanitizeWorkerProbeMetadata(sanitizeProbeMetadata(out));
      const res = corr(md);
      assert.equal(res.verdict, 'inconclusive');
      assert.match(res.explanation, /unattributed_errors/);
    });

    it('200x5 then 503 without Retry-After results in inconclusive (unattributed_errors)', async () => {
      let n = 0;
      const out = await runRateLimitCanaryProbe({
        url: 'https://app.example.com/',
        canary,
        rate_limit_canary: canary,
        declarations: decls,
        fetchFn: async () => {
          n += 1;
          return new Response('body', { status: n <= 5 ? 200 : 503 });
        },
      });
      const md = sanitizeWorkerProbeMetadata(sanitizeProbeMetadata(out));
      const res = corr(md);
      assert.equal(res.verdict, 'inconclusive');
      assert.match(res.explanation, /unattributed_errors/);
    });

    it('200x5 then 503 with Retry-After results in protected', async () => {
      let n = 0;
      const out = await runRateLimitCanaryProbe({
        url: 'https://app.example.com/',
        canary,
        rate_limit_canary: canary,
        declarations: decls,
        fetchFn: async () => {
          n += 1;
          if (n <= 5) return new Response('body', { status: 200 });
          return new Response('rate limited', { status: 503, headers: { 'retry-after': '30' } });
        },
      });
      const md = sanitizeWorkerProbeMetadata(sanitizeProbeMetadata(out));
      const res = corr(md);
      assert.equal(res.verdict, 'protected');
    });

    it('200x7 (allowed_before_limit > threshold) results in exposed', async () => {
      const out = await runRateLimitCanaryProbe({
        url: 'https://app.example.com/',
        canary,
        rate_limit_canary: canary,
        declarations: decls,
        fetchFn: async () => new Response('body', { status: 200 }),
      });
      const md = sanitizeWorkerProbeMetadata(sanitizeProbeMetadata(out));
      const res = corr(md);
      assert.equal(res.verdict, 'exposed');
    });
  });

  describe('Item 3: Clients must not set verification_basis', () => {
    const ctx = { tenantId: 'ten_r5', userId: 'u_r5', role: 'admin', scopes: ['*'] };

    it('dev patchFinding ignores client verification_basis and clears it on reopen', () => {
      resetStoreForTests();
      const s = getStore();
      s.findings = [{
        id: 'finding_r5_1',
        tenant_id: 'ten_r5',
        target_id: 'tgt_1',
        check_id: 'nfw.declared_deny_tcp.safe',
        status: 'open',
        verification_basis: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }];

      const patched = patchFinding(ctx, 'finding_r5_1', {
        status: 'resolved',
        verification_basis: 'manual_soc_verified',
      });
      assert.ok(patched);
      const stored = s.findings.find((f) => f.id === 'finding_r5_1');
      assert.equal(stored.verification_basis, null);

      patchFinding(ctx, 'finding_r5_1', {
        verification_basis: { nested: 'injected_object' },
      });
      assert.equal(stored.verification_basis, null);

      stored.verification_basis = 'passing_retest';
      patchFinding(ctx, 'finding_r5_1', { status: 'open' });
      assert.equal(stored.verification_basis, null);
    });
  });

  describe('Item 4: WAF-family edges count as CDN peers', () => {
    it('peerIsCdn returns true for Cloudflare waf-family edge IP', () => {
      assert.equal(peerIsCdn('104.16.0.10'), true);
    });

    it('peerIsCdn returns true for Imperva waf-family edge IP', () => {
      assert.equal(peerIsCdn('45.60.0.10'), true);
    });

    it('peerIsCdn returns true for Cloudflare cdn-family edge IP', () => {
      assert.equal(peerIsCdn('108.162.192.1'), true);
    });

    it('peerIsCdn returns false for non-edge IP', () => {
      assert.equal(peerIsCdn('198.51.100.10'), false);
    });

    it('correlateExternalOnlyVerdict on a declared-deny port to 104.16.0.10 gives inconclusive', () => {
      const decls = {
        network_policy: [{ protocol: 'tcp', port: 443, action: 'deny', address_family: 'any' }],
      };
      const verdict = correlateExternalOnlyVerdict({
        externalResult: 'connected',
        expectedBehavior: null,
        probeKind: 'tcp_connect',
        probeIoObserved: true,
        probeMetadata: {
          target_port: 443,
          address: '104.16.0.10',
          peer_is_cdn: peerIsCdn('104.16.0.10'),
          tcp_outcome: 'connected',
        },
        declarations: decls,
        checkId: 'nfw.declared_deny_tcp.safe',
      });
      assert.equal(verdict.verdict, 'inconclusive');
    });
  });

  describe('Item 5: Binding verification', () => {
    const check = getCheckById('nfw.origin_lockdown.safe');
    const target = { id: 'tgt_protected_1', tenant_id: 'ten_b5', kind: 'fqdn', value: 'app.example.com' };
    const declarations = { origin: { lockdown_expected: true } };

    it('active binding without verification fields returns origin_binding_required', () => {
      const targetWithBareBinding = {
        ...target,
        metadata: { control_declarations: declarations },
        origin_bindings: [{ id: 'b_1', status: 'active', protected_target_id: target.id, origin_target_id: 'orig_1' }],
      };
      const refusal = targetInputRefusal(check, targetWithBareBinding, declarations);
      assert.ok(refusal);
      assert.equal(refusal.error, 'origin_binding_required');
    });

    it('active binding with verified: true is accepted', () => {
      const targetWithVerifiedBinding = {
        ...target,
        metadata: { control_declarations: declarations },
        origin_bindings: [{ id: 'b_1', status: 'active', verified: true, protected_target_id: target.id, origin_target_id: 'orig_1' }],
      };
      const refusal = targetInputRefusal(check, targetWithVerifiedBinding, declarations);
      assert.equal(refusal, null);
    });

    it('active binding verified via records.targetVerifications is accepted', () => {
      const originBindings = {
        bindings: [{ id: 'b_1', status: 'active', protected_target_id: target.id, origin_target_id: 'orig_1' }],
        records: {
          targetVerifications: [{ target_id: 'orig_1', tenant_id: 'ten_b5', state: 'dns_verified' }],
        },
      };
      const refusal = targetInputRefusal(check, target, declarations, { originBindings });
      assert.equal(refusal, null);
    });

    it('active binding with unverified origin in records returns origin_binding_required', () => {
      const originBindings = {
        bindings: [{ id: 'b_1', status: 'active', protected_target_id: target.id, origin_target_id: 'orig_1' }],
        records: {
          targetVerifications: [{ target_id: 'orig_1', tenant_id: 'ten_b5', state: 'unverified' }],
        },
      };
      const refusal = targetInputRefusal(check, target, declarations, { originBindings });
      assert.ok(refusal);
      assert.equal(refusal.error, 'origin_binding_required');
    });

    it('dev targetRuleCoverage matches bindings by origin_target_id as well as protected_target_id', () => {
      resetStoreForTests();
      const s = getStore();
      s.targetGroups = [{ id: 'grp_cov', tenant_id: 'ten_cov', name: 'Cov Group' }];
      const originTgt = { id: 'orig_tgt_1', tenant_id: 'ten_cov', target_group_id: 'grp_cov', kind: 'ip', value: '198.51.100.20' };
      s.targets = [originTgt];
      s.originBindings = [{
        id: 'ob_cov_1',
        tenant_id: 'ten_cov',
        protected_target_id: 'prot_tgt_1',
        origin_target_id: originTgt.id,
        status: 'active',
      }];
      const cov = targetRuleCoverage({ tenantId: 'ten_cov' }, originTgt.id);
      assert.ok(cov);
      const originCat = cov.categories.find((c) => c.id === 'origin_lockdown');
      assert.ok(originCat);
    });
  });

  describe('Item 6: All refusal codes in checks.mjs are documented in docs/api.md', () => {
    it('every error code returned by targetInputRefusal / additionalInputRefusal is in docs/api.md', () => {
      const checksPath = path.resolve('src/contracts/checks.mjs');
      const checksSource = fs.readFileSync(checksPath, 'utf8');
      const docsPath = path.resolve('docs/api.md');
      const docsSource = fs.readFileSync(docsPath, 'utf8');

      const matches = [...checksSource.matchAll(/error:\s*'([^']+)'/g)].map((m) => m[1]);
      const uniqueCodes = [...new Set(matches)];
      assert.ok(uniqueCodes.length >= 11, `Expected at least 11 refusal codes, found ${uniqueCodes.length}`);

      for (const code of uniqueCodes) {
        assert.ok(
          docsSource.includes(`\`${code}\``),
          `Refusal code '${code}' in checks.mjs is missing from docs/api.md`,
        );
      }
    });
  });
});
