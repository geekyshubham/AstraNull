import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { classifyDnsPath, declaredHost } from '../../apps/web/react/src/pages/refined/targets-dns-path.ts';
import { designVariantStorageKey, resolveDesignVariant } from '../../apps/web/react/src/lib/design-variant.ts';
import { resolveOutsideInDnsHints } from '../../src/lib/outsideInWafScanner.mjs';

const SRC = new URL('../../apps/web/react/src/', import.meta.url);
const read = (path) => readFileSync(new URL(path, SRC), 'utf8');

function topLevelParts(selector) {
  const parts = [];
  let depth = 0;
  let current = '';
  for (const char of selector) {
    if (char === '(') depth += 1;
    if (char === ')') depth -= 1;
    if (char === ',' && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  return [...parts, current];
}

function edge(evidence, extra = {}) {
  return { status: 'detected', observed_at: '2026-10-01T10:00:00.000Z', evidence, ...extra };
}

describe('Refined targets DNS path (recorded observation only)', () => {
  it('reports CNAME when the recorded chain holds an alias after the queried host', () => {
    const path = classifyDnsPath({
      kind: 'fqdn',
      value: 'App.Example.com',
      edgeDetection: edge({
        dns_cname_chain: ['app.example.com', 'app.example.com.cdn.cloudflare.net.'],
        dns_resolved_ips: ['104.16.1.1'],
        cname_cdn_matches: [{ provider: 'cloudflare', family: 'cdn', host: 'app.example.com.cdn.cloudflare.net' }],
      }),
    });
    assert.equal(path.kind, 'cname');
    assert.equal(path.recordLabel, 'CNAME');
    assert.deepEqual(path.aliases, ['app.example.com.cdn.cloudflare.net']);
    assert.deepEqual(path.aliasMatch, { provider: 'cloudflare', family: 'cdn' });
    assert.equal(path.observedAt, '2026-10-01T10:00:00.000Z');
  });

  it('ignores a provider match whose host is not one of the observed aliases', () => {
    const path = classifyDnsPath({
      kind: 'fqdn',
      value: 'app.example.com',
      edgeDetection: edge({
        dns_cname_chain: ['app.example.com', 'lb.example.net'],
        cname_matches: [{ provider: 'akamai', type: 'waf', host: 'other.edgekey.net' }],
      }),
    });
    assert.equal(path.kind, 'cname');
    assert.equal(path.aliasMatch, null);
  });

  it('reports A, AAAA, or both without treating the seeded hostname as a completed CNAME lookup', () => {
    const v4 = classifyDnsPath({
      kind: 'fqdn',
      value: 'origin.example.com',
      edgeDetection: edge({
        dns_cname_chain: ['origin.example.com'],
        dns_resolved_ips: ['203.0.113.10'],
        address_matches: [{ family: 'cloud', provider: 'hetzner' }],
      }),
    });
    assert.equal(v4.kind, 'address_unchecked');
    assert.doesNotMatch(v4.summary, /No CNAME/i);
    assert.match(v4.summary, /completion is not recorded/);
    assert.equal(v4.recordLabel, 'A');
    assert.deepEqual(v4.addressMatches, [{ provider: 'hetzner', family: 'cloud' }]);
    const dual = classifyDnsPath({
      kind: 'url',
      value: 'https://www.example.com/health',
      edgeDetection: edge({ dns_cname_chain: ['www.example.com'], dns_resolved_ips: ['198.51.100.7', '2001:db8::7'] }),
    });
    assert.equal(dual.host, 'www.example.com');
    assert.equal(dual.recordLabel, 'A + AAAA');
    const v6 = classifyDnsPath({ kind: 'fqdn', value: 'v6.example.com', edgeDetection: edge({ dns_cname_chain: ['v6.example.com'], dns_resolved_ips: ['2001:db8::1'] }) });
    assert.equal(v6.recordLabel, 'AAAA');
  });

  it('does not infer a negative CNAME answer when only addresses are recorded', () => {
    const path = classifyDnsPath({ kind: 'fqdn', value: 'api.example.com', edgeDetection: edge({ dns_resolved_ips: ['203.0.113.20'] }) });
    assert.equal(path.kind, 'address_unchecked');
    assert.match(path.summary, /CNAME lookup completion is not recorded/);
  });

  it('keeps a CNAME resolver timeout indeterminate even when an address lookup succeeds', async () => {
    const observed = await resolveOutsideInDnsHints('api.example.com', {
      resolveCname: async () => { throw Object.assign(new Error('resolver timeout'), { code: 'ETIMEOUT' }); },
      resolve4: async () => ['203.0.113.20'],
      resolve6: async () => [],
    });
    assert.deepEqual(observed.cname_chain, ['api.example.com']);
    const path = classifyDnsPath({ kind: 'fqdn', value: 'api.example.com', edgeDetection: edge({ dns_cname_chain: observed.cname_chain, dns_resolved_ips: observed.resolved_ips }) });
    assert.equal(path.kind, 'address_unchecked');
    assert.doesNotMatch(path.summary, /No CNAME/i);
  });

  it('shows Not observed with no observation, or an observation without DNS answers', () => {
    assert.equal(classifyDnsPath({ kind: 'fqdn', value: 'new.example.com', edgeDetection: null }).kind, 'not_observed');
    const empty = classifyDnsPath({ kind: 'fqdn', value: 'new.example.com', edgeDetection: edge({ dns_cname_chain: ['new.example.com'] }) });
    assert.equal(empty.kind, 'not_observed');
    assert.equal(empty.recordLabel, 'Not observed');
  });

  it('treats declared IPs and IP-based TCP services as having no DNS record, without any observation', () => {
    assert.equal(classifyDnsPath({ kind: 'ip', value: '203.0.113.10', edgeDetection: null }).kind, 'declared_ip');
    assert.equal(classifyDnsPath({ kind: 'tcp', value: '203.0.113.10:443', edgeDetection: null }).kind, 'declared_ip');
    assert.equal(classifyDnsPath({ kind: 'tcp', value: '[2001:db8::5]:8443', edgeDetection: null }).kind, 'declared_ip');
    assert.equal(declaredHost('tcp', 'db.example.com:5432'), 'db.example.com');
    assert.equal(declaredHost('canary', 'https://status.example.com'), 'status.example.com');
  });
});

describe('Targets design variant', () => {
  let previousWindow;
  beforeEach(() => { previousWindow = globalThis.window; });
  afterEach(() => { globalThis.window = previousWindow; });

  function installWindow(hash) {
    const writes = [];
    globalThis.window = {
      location: { hash, pathname: '/app', search: '' },
      localStorage: { getItem: () => null, setItem: (key, value) => writes.push([key, value]) },
    };
    return writes;
  }

  it('opens Refined from #targets?variant=refined and stays Classic by default', () => {
    installWindow('#targets?variant=refined');
    assert.equal(resolveDesignVariant('targets', false), 'refined');
    installWindow('#targets');
    assert.equal(resolveDesignVariant('targets', false), 'classic');
    installWindow('#runs?variant=refined');
    assert.equal(resolveDesignVariant('targets', true), 'classic', 'another route’s override never applies to targets');
    const writes = installWindow('#targets?variant=refined');
    resolveDesignVariant('targets', true);
    assert.deepEqual(writes, [[designVariantStorageKey('targets'), 'refined']]);
  });

  it('wires the staff-only switch and keeps Classic as the unchanged default inventory', () => {
    const page = read('pages/targets-page.tsx');
    assert.match(page, /const showVariantSwitch = session\.principal === 'staff';/);
    assert.match(page, /useDesignVariant\('targets', \{ persist: showVariantSwitch \}\)/);
    assert.match(page, /\{showVariantSwitch \? <VariantSwitch value=\{variant\} onChange=\{setVariant\} \/> : null\}/);
    assert.match(page, /\{!cohort && variant !== 'refined' \? \(\s*<Card>/);
    assert.match(page, /\{!cohort && variant === 'refined' \? \(\s*<TargetsRefinedInventory/);
    assert.match(page, /rows=\{filtered\.map\(describeTarget\)\}/, 'Refined shows the same filtered records');
  });

  it('keeps the Classic permission gates in Refined rows and reads DNS paths with bounded GETs only', () => {
    const refined = read('pages/refined/targets-refined.tsx');
    assert.match(refined, /const promptVerify = !row\.verified && canWriteTargets;/);
    assert.match(refined, /\{row\.verified && canRunChecks \? \(\s*<AnchorButton/);
    assert.equal((refined.match(/&tab=validate/g) ?? []).length, 1);
    assert.equal((refined.match(/\{canWriteTargets \? \(\s*<Button size="icon"/g) ?? []).length, 2, 'Edit tags and Remove stay behind target_group:write');
    assert.match(refined, /requestJson\(props\.config, props\.session, `\/v1\/targets\/\$\{encodeURIComponent\(row\.id\)\}`\)/);
    assert.doesNotMatch(refined, /method: '(POST|PATCH|PUT|DELETE)'/, 'reading a DNS path never writes or starts a probe');
    assert.match(refined, /export const DNS_READ_BATCH_LIMIT = 25;/);
    assert.match(refined, /row\.item\.dns_observation/, 'the list API field fills the DNS column without a per-row read');
    assert.match(refined, /\{legacyRowCount > 0 \? \(/, 'the batch read only appears when the list lacks dns_observation');
    assert.match(refined, /CNAME vs A record: what changes/);
    assert.match(refined, /<details className="rf-dns-explainer">/);
    assert.match(refined, /variant="skeleton" title="Loading targets"/);
    assert.match(refined, /loadError=\{props\.loadError\}/);
  });

  it('does not present DNS record types as proof of protection or direct reachability', () => {
    const source = read('pages/refined/targets-refined.tsx');
    assert.match(source, /Neither an alias nor an address record alone proves/);
    assert.match(source, /An alias does not establish origin reachability or lockdown/);
    assert.match(source, /An origin address can still have network filtering/);
    assert.doesNotMatch(source, /stays reachable if its address is known|nothing filters traffic first|The provider&apos;s edge answers first/);
  });

  it('scopes Refined target styles under .refined and uses tokens only', () => {
    const css = read('pages/refined/targets-refined.css');
    const tsx = read('pages/refined/targets-refined.tsx');
    const selectors = css
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .split('}')
      .map((block) => block.split('{').at(-2)?.trim() ?? '')
      .filter((selector) => selector && !selector.startsWith('@') && !/^(from|to|\d+%)$/.test(selector));
    assert.ok(selectors.length > 20);
    for (const selector of selectors) {
      for (const part of topLevelParts(selector)) assert.match(part.trim(), /^\.refined\.rf-targets\b/, `unscoped selector: ${part}`);
    }
    for (const source of [css, tsx]) {
      assert.doesNotMatch(source, /#[0-9a-f]{3,8}\b|\brgba?\(|\bhsla?\(|\boklch\(/i, 'no raw colors');
    }
  });
});
