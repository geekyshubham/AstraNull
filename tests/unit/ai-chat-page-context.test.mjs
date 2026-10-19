import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MAX_FACTS,
  MAX_FACT_VALUE,
  MAX_FILTERS,
  buildPageContext,
  contextIds,
  describePageContext,
  parseRouteHash,
  pageSuggestions,
  sanitizePageContext,
} from '../../apps/web/react/src/lib/assistant-page-context.mjs';

const data = {
  state: { readiness: { score: 62 } },
  targets: [
    { id: 't1', value: 'shop.example.com', kind: 'fqdn', verification_state: 'dns_verified' },
    { id: 't2', value: 'api.example.com', kind: 'fqdn', verification_state: 'unverified' },
  ],
  findings: [
    { id: 'f1', title: 'Origin reachable directly', severity: 'high', status: 'open', target_id: 't1', check_id: 'origin_exposure' },
    { id: 'f2', title: 'No rate limit', severity: 'medium', status: 'closed', target_id: 't2' },
  ],
  runs: [],
  checks: [],
  findingsMeta: { total: 2 },
};

describe('assistant page context', () => {
  it('parses the route and query from the hash', () => {
    assert.deepEqual(parseRouteHash('#target-detail?id=t1&tab=validate'), { route: 'target-detail', params: { id: 't1', tab: 'validate' } });
    assert.deepEqual(parseRouteHash(''), { route: 'dashboard', params: {} });
    assert.equal(parseRouteHash('#<script>?x=1').route, 'script');
  });

  it('derives the entity, tab and facts from the route alone', () => {
    const page = buildPageContext({ route: 'target-detail', params: { id: 't1', tab: 'validate' }, data });
    assert.equal(page.kind, 'target');
    assert.equal(page.title, 'Target detail');
    assert.deepEqual(page.entity, { type: 'target', id: 't1' });
    assert.equal(page.tab, 'validate');
    assert.equal(page.facts.Target, 'shop.example.com');
    assert.equal(page.facts.Ownership, 'dns_verified');
    assert.equal(page.facts['Open findings (loaded)'], '1');
    assert.equal(page.filters, undefined);
  });

  it('reads the finding group key and dashboard facts', () => {
    assert.equal(buildPageContext({ route: 'finding-group-detail', params: { key: 'check:origin' } }).kind, 'finding_group');
    const dashboard = buildPageContext({ route: 'dashboard', data });
    assert.equal(dashboard.facts['Readiness score'], '62/100');
    assert.equal(dashboard.facts['Ownership verified'], '1');
  });

  it('lets the page for the same route add and override facts, and ignores a stale page', () => {
    const published = { route: 'findings', filters: { status: 'open', severity: undefined }, facts: { 'Findings total': 40, 'SLA breaches': 3 } };
    const page = buildPageContext({ route: 'findings', params: { status: 'all' }, data, published });
    assert.equal(page.filters.status, 'open');
    assert.equal(page.facts['Findings total'], '40');
    assert.equal(page.facts['SLA breaches'], '3');
    const stale = buildPageContext({ route: 'targets', data, published });
    assert.equal(stale.facts['SLA breaches'], undefined);
    assert.equal(stale.filters, undefined);
  });

  it('never sends secrets or session parameters', () => {
    const page = buildPageContext({
      route: 'targets',
      params: { tenant: 'acme', access_token: 'abc', q: 'shop', ev_body: 'raw' },
      published: {
        route: 'targets',
        filters: { api_key: 'x', note: 'Bearer abcdefghijklmnop' },
        facts: { Password: 'hunter2', Header: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig', Pem: '-----BEGIN PRIVATE KEY-----', Token: 'ghp_abcdefghijklmnopqrstu', Count: 3 },
      },
    });
    assert.deepEqual(page.filters, { q: 'shop' });
    assert.deepEqual(page.facts, { 'Declared targets': '0', Count: '3' });
  });

  it('caps filters, facts and value length', () => {
    const many = Object.fromEntries(Array.from({ length: 40 }, (_, index) => [`k${index}`, `v${index}`]));
    const page = sanitizePageContext({ route: 'dashboard', filters: many, facts: { ...many, long: 'x'.repeat(500) } });
    assert.equal(Object.keys(page.filters).length, MAX_FILTERS);
    assert.equal(Object.keys(page.facts).length, MAX_FACTS);
    const long = sanitizePageContext({ route: 'dashboard', facts: { long: 'x'.repeat(500) } });
    assert.equal(long.facts.long.length, MAX_FACT_VALUE);
  });

  it('drops malformed context and unknown entity types', () => {
    assert.equal(sanitizePageContext(null), null);
    assert.equal(sanitizePageContext({ route: '' }), null);
    assert.equal(sanitizePageContext([]), null);
    const page = sanitizePageContext({ route: 'dashboard', entity: { type: 'tenant', id: 'x' }, title: 'A\u0000B' });
    assert.equal(page.entity, undefined);
    assert.equal(page.title, 'A B');
  });

  it('maps the entity to the record id the server resolves', () => {
    assert.deepEqual(contextIds({ route: 'x', title: '', kind: '', entity: { type: 'finding', id: 'f1' } }), { finding_id: 'f1' });
    assert.deepEqual(contextIds({ route: 'x', title: '', kind: '', entity: { type: 'report', id: 'r1' } }), {});
    assert.deepEqual(contextIds(null), {});
  });

  it('describes the page for the chip and suggests page-specific questions', () => {
    const page = buildPageContext({ route: 'target-detail', params: { id: 't1' }, data });
    assert.equal(describePageContext(page), 'Target detail · shop.example.com');
    assert.equal(describePageContext(null), '');
    assert.ok(pageSuggestions('dashboard').some((prompt) => /chart/i.test(prompt)));
    assert.notDeepEqual(pageSuggestions('target'), pageSuggestions('findings'));
    assert.ok(pageSuggestions('unknown-kind').length > 0);
  });
});
