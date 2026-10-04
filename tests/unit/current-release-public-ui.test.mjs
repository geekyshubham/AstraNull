import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer as createViteServer } from 'vite';
import { assessPassword } from '../../src/lib/password.mjs';
import { validateSignupRequestInput, SIGNUP_REQUEST_STATES } from '../../src/contracts/signupIntake.mjs';
import { findingGroupHref, findingGroupKey } from '../../apps/web/react/src/lib/finding-groups.mjs';
import { buildEvidenceInspectorHref } from '../../apps/web/react/src/lib/evidence-inspector.mjs';

const GROUP_CONTEXT = { targets: [{ id: 'tgt_1', name: 'checkout.shop.example' }], checks: [] };
/** Real findings shaped like the API; keys and hrefs come from the shipped builders. */
const GROUP_FINDINGS = [
  { id: 'fnd_a', check_id: 'http.rate_limit.safe', target_id: 'tgt_1', title: 'Rate limiting missing on /login | burst (50%) \u2014 "quoted" \u6771\u4eac' },
  { id: 'fnd_b', check_id: 'dns.zone_transfer', verdict: 'exposed', title: '' },
  { id: 'fnd_c', title: 'Origin reachable directly' },
];

/** Round-trip a portal hash through the sign-in URL exactly as the browser would. */
function throughSignIn(mod, hash) {
  const loginUrl = mod.buildLoginReturnUrl('/login', { hash, reason: 'session_expired' });
  const next = new URLSearchParams(loginUrl.split('?')[1] ?? '').get('next');
  return mod.sanitizeReturnHash(next);
}

const PAGE = 'apps/web/react/src/pages/public-pages.tsx';
const CSS = 'apps/web/react/src/pages/public-landing.css';
const source = readFileSync(PAGE, 'utf8');
const css = readFileSync(CSS, 'utf8');

describe('current-release public pages', () => {
  let vite;
  let mod;

  before(async () => {
    vite = await createViteServer({
      configFile: path.resolve('vite.config.ts'),
      server: { middlewareMode: true },
      appType: 'custom',
      logLevel: 'silent',
    });
    mod = await vite.ssrLoadModule('/src/pages/public-pages.tsx');
  });

  after(async () => {
    await vite?.close();
  });

  describe('safe return-to-intent contract', () => {
    it('keeps the selection params each route reads and drops the rest', () => {
      assert.equal(mod.sanitizeReturnHash('#findings'), '#findings');
      assert.equal(
        mod.sanitizeReturnHash('target-detail?id=tgt_abc&token=pwi_secret&tab=evidence&check=http.rate_limit.safe&q=free+text'),
        '#target-detail?id=tgt_abc&tab=evidence&check=http.rate_limit.safe',
      );
      assert.equal(mod.sanitizeReturnHash('#check-detail?id=chk_1&policy=pol_2&target=tgt_3&password=x'), '#check-detail?id=chk_1&policy=pol_2&target=tgt_3');
      assert.equal(mod.sanitizeReturnHash('#checks?target=tgt_3&q=secret'), '#checks?target=tgt_3');
      assert.equal(mod.sanitizeReturnHash('#finding-detail?entity_id=fnd_1'), '#finding-detail?id=fnd_1');
      assert.equal(mod.sanitizeReturnHash('#findings?id=fnd_1&key=chk|v%3Aexposed'), '#findings', 'list routes do not read id or key');
      assert.equal(mod.resolveSafeReturnPath('#finding-detail?id=fnd_1', '/app'), '/app#finding-detail?id=fnd_1');
      assert.equal(mod.returnDestinationLabel('#findings'), 'Findings');
    });

    it('rejects staff, unknown, external and malformed destinations and values', () => {
      for (const unsafe of ['#admin', '#tenant-detail?id=ten_1', '#not-a-route', 'https://evil.example/#findings', '//evil.example', '#findings/../admin', '', null, `#${'a'.repeat(2100)}`]) {
        assert.equal(mod.sanitizeReturnHash(unsafe), null, String(unsafe));
      }
      assert.equal(mod.sanitizeReturnHash('#finding-detail?id=<script>'), '#finding-detail');
      assert.equal(mod.sanitizeReturnHash('#target-detail?id=tgt_1&tab=Evidence%20Now&check=a/b'), '#target-detail?id=tgt_1');
      assert.equal(mod.resolveSafeReturnPath('#findings', '//evil.example'), '/app#findings');
    });

    it('preserves real finding-group keys through sign-in, byte for byte after decoding', () => {
      for (const finding of GROUP_FINDINGS) {
        const key = findingGroupKey(finding, GROUP_CONTEXT);
        const href = findingGroupHref(key);
        assert.equal(mod.parseFindingGroupReturnKey(key), key);
        const restored = throughSignIn(mod, href);
        assert.ok(restored?.startsWith('#finding-group-detail?key='), restored);
        assert.equal(mod.returnHashParam(restored, 'key'), key, finding.id);
        assert.equal(mod.returnHashParam(href, 'key'), key, 'destination reads the same key it was linked with');
      }
    });

    it('rejects group keys that are not canonical, bounded and free of control or credential text', () => {
      const real = findingGroupKey(GROUP_FINDINGS[1], GROUP_CONTEXT);
      const encode = (check, issue) => `${encodeURIComponent(check)}|${encodeURIComponent(issue)}`;
      const unsafe = [
        `${real}|extra`,
        'dns.zone_transfer',
        '|v%3Aexposed',
        'dns.zone_transfer|',
        'dns.zone_transfer|v:exposed',
        'dns.zone_transfer|v%3aexposed',
        'dns.zone_transfer|v%3Aexposed%ZZ',
        encode('dns.zone_transfer', 'v:exposed\u0000'),
        encode('dns.zone_transfer', 't:line\nbreak'),
        encode('chk<script>', 'v:exposed'),
        encode('../admin', 'v:exposed'),
        encode('dns.zone_transfer', 'x:unknown-form'),
        encode('dns.zone_transfer', 't:pwi_live-invite-token'),
        encode('dns.zone_transfer', 't:bearer abc'),
        encode('dns.zone_transfer', `t:${'eyJhbGciOiJIUzI1NiJ9'}.payload.sig`),
        encode('dns.zone_transfer', `t:${'a'.repeat(300)}`),
      ];
      for (const key of unsafe) {
        assert.equal(mod.parseFindingGroupReturnKey(key), null, key);
        assert.equal(mod.sanitizeReturnHash(`#finding-group-detail?key=${encodeURIComponent(key)}`), '#finding-group-detail', key);
      }
    });

    it('keeps evidence-inspector state only through the shared inspector schema', () => {
      const base = '#target-detail?id=tgt_1&tab=checks&check=http.rate_limit.safe';
      const withInspector = buildEvidenceInspectorHref(
        { entry: 'check_result', target_id: 'tgt_1', check_id: 'http.rate_limit.safe', test_run_id: 'run_9' },
        base,
      );
      const restored = throughSignIn(mod, `${withInspector}&token=pwr_secret&raw_payload=x`);
      assert.equal(mod.returnHashParam(restored, 'inspect'), 'check_result');
      assert.equal(mod.returnHashParam(restored, 'ev_run'), 'run_9');
      assert.equal(mod.returnHashParam(restored, 'check'), 'http.rate_limit.safe');
      assert.equal(mod.returnHashParam(restored, 'token'), null);
      assert.equal(mod.returnHashParam(restored, 'raw_payload'), null);

      const groupHref = findingGroupHref(findingGroupKey(GROUP_FINDINGS[0], GROUP_CONTEXT));
      const member = buildEvidenceInspectorHref({ entry: 'group_member', finding_id: 'fnd_a' }, groupHref);
      const memberRestored = throughSignIn(mod, member);
      assert.equal(mod.returnHashParam(memberRestored, 'key'), findingGroupKey(GROUP_FINDINGS[0], GROUP_CONTEXT));
      assert.equal(mod.returnHashParam(memberRestored, 'ev_finding'), 'fnd_a');

      assert.equal(mod.sanitizeReturnHash('#findings?inspect=finding'), '#findings', 'incomplete ref is dropped');
      assert.equal(mod.sanitizeReturnHash('#findings?inspect=finding&ev_finding=..%2Fx'), '#findings');
      assert.equal(mod.sanitizeReturnHash('#findings?inspect=shell&ev_finding=fnd_1'), '#findings');
    });

    it('builds a sign-in URL with next and reason, leaving identity-provider URLs untouched', () => {
      assert.equal(
        mod.buildLoginReturnUrl('/login', { hash: '#finding-detail?id=fnd_1&token=x', reason: 'session_expired' }),
        `/login?next=${encodeURIComponent('#finding-detail?id=fnd_1')}&reason=session_expired`,
      );
      assert.equal(mod.buildLoginReturnUrl('/login', { hash: '#admin', reason: 'bogus' }), '/login');
      assert.equal(mod.buildLoginReturnUrl('https://idp.example/authorize', { hash: '#findings' }), 'https://idp.example/authorize');
      assert.equal(mod.parseLoginReturnReason('signed_out'), 'signed_out');
      assert.equal(mod.parseLoginReturnReason('access_denied'), null);
    });
  });

  describe('signup lifecycle derives only from recorded state', () => {
    it('maps every backend state and never claims the account is active', () => {
      for (const state of SIGNUP_REQUEST_STATES) {
        const stages = mod.signupLifecycleStages(state);
        const next = mod.signupNextStep(state);
        if (state === 'rejected') {
          assert.deepEqual(stages, []);
          assert.equal(next.canSignIn, false);
          continue;
        }
        assert.equal(stages.filter((stage) => stage.status === 'current').length, 1, state);
        assert.equal(stages.at(-1).status, 'untracked', 'password setup is never inferred');
        assert.equal(next.canSignIn, state === 'customer_invited', state);
        assert.ok(!mod.signupStateLabel(state).startsWith('Recorded as'), state);
      }
      assert.deepEqual(mod.signupLifecycleStages('mystery_state'), []);
      assert.equal(mod.signupStateLabel('mystery_state'), 'Recorded as mystery_state');
      assert.equal(mod.signupNextStep('approved').headline, 'You cannot sign in yet.');
    });
  });

  describe('password requirement feedback mirrors the server policy', () => {
    it('agrees with assessPassword on length and character classes', () => {
      const samples = ['', 'short', 'alllowercaseletters', 'Lowercase-only1', 'NoDigitsHere!!', 'Harbor-lantern-42', 'abcdefghijK1', 'ABCDEFGHIJK1!', 'x'.repeat(201)];
      for (const sample of samples) {
        const ui = Object.fromEntries(mod.passwordRequirementStatus(sample).map((item) => [item.id, item.met]));
        const server = assessPassword(sample).failures;
        assert.equal(ui.length, !server.includes('too_short') && !server.includes('too_long'), `length: ${sample.slice(0, 20)}`);
        if (sample.length <= 200) {
          assert.equal(ui.classes, !server.includes('insufficient_character_classes'), `classes: ${sample}`);
        }
      }
      assert.equal(mod.PASSWORD_MIN_LENGTH, 12);
      assert.equal(mod.PASSWORD_MAX_LENGTH, 200);
    });
  });

  describe('request-access validation mirrors the intake contract', () => {
    it('flags the same required fields as validateSignupRequestInput', () => {
      const valid = {
        organization_name: 'Northwind Ferries',
        contact_name: 'Rowan Achebe',
        contact_email: 'rowan@ferries.test',
        intended_use: 'Validate public booking site',
        requested_plan: 'professional',
        region: 'eu',
      };
      assert.deepEqual(mod.validateSignupDraft(valid), {});
      assert.equal(validateSignupRequestInput(valid).ok, true);
      const invalid = { ...valid, organization_name: 'N', contact_email: 'rowan@', intended_use: 'short' };
      const ui = Object.keys(mod.validateSignupDraft(invalid)).sort();
      const server = validateSignupRequestInput(invalid).errors.filter((field) => field !== 'contact_email_domain').sort();
      assert.deepEqual(ui, server);
    });
  });

  describe('support contact is shown only when the deployment publishes one', () => {
    it('accepts valid email or https and rejects everything else', () => {
      assert.equal(mod.publicSupportContact({}), null);
      assert.equal(mod.publicSupportContact({ support_email: 'not-an-email' }), null);
      assert.equal(mod.publicSupportContact({ support_url: 'javascript:alert(1)' }), null);
      assert.equal(mod.publicSupportContact({ support_url: 'http://insecure.example' }), null);
      assert.deepEqual(mod.publicSupportContact({ support_email: 'help@astranull.test' }), { label: 'help@astranull.test', href: 'mailto:help@astranull.test' });
      assert.deepEqual(mod.publicSupportContact({ support_url: 'https://support.astranull.test/access' }), { label: 'support.astranull.test/access', href: 'https://support.astranull.test/access' });
    });
  });

  describe('unavailable routes keep not-found, denied and missing records distinct', () => {
    it('renders different explanations and never echoes query identifiers', () => {
      const render = (props) => renderToStaticMarkup(createElement(mod.PortalUnavailablePage, props));
      const notFound = render({ kind: 'not-found', requestedHash: '#not-a-route?token=pwi_secret' });
      const denied = render({ kind: 'access-denied', requestedHash: '#audit', requestedLabel: 'Audit log', role: 'viewer' });
      const missing = render({ kind: 'record-missing', requestedHash: '#target-detail?id=tgt_gone', requestedLabel: 'Target', parentHref: '#targets', parentLabel: 'Back to targets' });

      assert.match(notFound, /This page is unavailable\./);
      assert.match(notFound, /#not-a-route/);
      assert.doesNotMatch(notFound, /pwi_secret|token=/);
      assert.match(denied, /You do not have access to this page\./);
      assert.match(denied, /Audit log is not available to the viewer role\. Nothing from it was loaded\./);
      assert.match(missing, /This record is not available\./);
      assert.match(missing, /No placeholder values are shown/);
      assert.match(missing, /href="#targets"/);
      assert.doesNotMatch(missing, /tgt_gone/);
      for (const html of [notFound, denied, missing]) {
        assert.doesNotMatch(html, /Showing Dashboard instead|healthy|protected/i);
      }
      assert.equal(mod.displayRequestedRoute('#a b<c>?x=1'), '#abc');
    });
  });

  describe('source safety', () => {
    it('keeps one-time tokens and passwords out of persistence and logs', () => {
      assert.doesNotMatch(source, /localStorage/);
      assert.doesNotMatch(source, /sessionStorage/);
      assert.doesNotMatch(source, /console\.(log|info|warn|error|debug)/);
      assert.doesNotMatch(source, /onPaste|preventDefault\(\);?\s*\/\/\s*paste/i);
      assert.match(source, /url\.searchParams\.delete\('token'\)/);
      assert.match(source, /window\.history\.replaceState\(\{\}, '', `\$\{url\.pathname\}\$\{url\.search\}\$\{url\.hash\}`\)/);
      assert.match(source, /id=\{`\$\{idPrefix\}-new`\}[\s\S]*autoComplete="new-password"/);
    });

    it('states the no-access-first product rules in visible landing copy without overclaiming', () => {
      assert.match(source, /checks customer-declared targets from outside your network, with no required cloud credentials and no automatic IP inventory discovery\./);
      assert.doesNotMatch(source, /proves DDoS readiness/i);
      assert.match(source, /does not certify protection or measure volumetric capacity/);
    });

    it('labels recovery as a request, never as a confirmed send', () => {
      const requestPage = source.slice(source.indexOf('function RequestPasswordResetPage'), source.indexOf('/* ── Password fields shared'));
      assert.match(requestPage, />Request recovery instructions<\/Button>/);
      assert.doesNotMatch(requestPage, /Send recovery instructions|instructions (?:were|have been) sent/i);
    });

    it('drops deferred high-scale intake and SOC marketing from the public surface', () => {
      assert.doesNotMatch(source, /high_scale_interest/);
      assert.doesNotMatch(source, /HighScaleSection|SOC_STAGES|Escalate through the SOC/);
      assert.doesNotMatch(css, /public-lane/);
      assert.match(source, /Illustrative example with invented data\. It is not a customer result\./);
    });

    it('does not let a production deployment pick its own role', () => {
      assert.match(source, /const stagingLane = isDevHeaders \|\| \(config\.bundledLoginEnabled && !idpRedirect\);/);
      assert.match(source, /const showStagingRolePicker = stagingLane && \(!passwordLane \|\| stagingBypass\);/);
    });

    it('uses no em dash in public copy', () => {
      assert.doesNotMatch(source, /—/);
      assert.doesNotMatch(css, /—/);
    });

    it('honours reduced motion for every public transition', () => {
      const reduced = css.slice(css.lastIndexOf('@media (prefers-reduced-motion: reduce)'));
      for (const selector of ['.public-app .btn:active:not(:disabled)', '.public-landing .public-example-index', '.public-app .public-requirements li svg']) {
        assert.ok(reduced.includes(selector), selector);
      }
    });
  });
});
