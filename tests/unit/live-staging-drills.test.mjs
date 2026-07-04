import assert from 'node:assert/strict';
import { describe, it, afterEach } from 'node:test';
import { parseArgs as parseOidcArgs, runLiveOidcStagingLogin } from '../../scripts/run-live-oidc-staging-login.mjs';
import { parseArgs as parseRunbookArgs, runOperatorRunbookExercise } from '../../scripts/run-operator-runbook-exercise.mjs';
import { parseArgs as parsePromotionArgs } from '../../scripts/production-promotion-attest.mjs';

describe('live staging drill CLI parsers', () => {
  it('parseArgs for OIDC login returns --base-url value', () => {
    const opts = parseOidcArgs(['--base-url', 'https://staging.example.test', '--release-id', 'rel-test']);
    assert.equal(opts.baseUrl, 'https://staging.example.test');
    assert.equal(opts.releaseId, 'rel-test');
  });

  it('parseArgs for OIDC login throws when flag value is missing', () => {
    assert.throws(
      () => parseOidcArgs(['--base-url']),
      /Missing value for --base-url/,
    );
  });

  it('parseArgs for operator runbook returns --base-url value', () => {
    const opts = parseRunbookArgs(['--base-url', 'https://staging.example.test', '--environment', 'staging']);
    assert.equal(opts.baseUrl, 'https://staging.example.test');
    assert.equal(opts.environment, 'staging');
  });

  it('parseArgs for operator runbook throws when flag value is missing', () => {
    assert.throws(
      () => parseRunbookArgs(['--release-id']),
      /Missing value for --release-id/,
    );
  });

  it('parseArgs for production promotion attest reads --base-url', () => {
    const opts = parsePromotionArgs(['--base-url', 'https://hosted.example.test']);
    assert.equal(opts.baseUrl, 'https://hosted.example.test');
  });
});

describe('operator runbook exercise edge cases', () => {
  let originalFetch;

  afterEach(() => {
    if (originalFetch) globalThis.fetch = originalFetch;
  });

  it('fails when /health is not ok', async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === '/health') return new Response('down', { status: 503 });
      return new Response('{}', { status: 200 });
    };
    await assert.rejects(
      () => runOperatorRunbookExercise({
        baseUrl: 'http://127.0.0.1:9',
        releaseId: 'rel-health-fail',
        environment: 'staging',
        out: '/tmp/runbook-health-fail.json',
      }),
      /health/,
    );
  });

  it('fails when /ready is not ready', async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === '/health') {
        return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
      }
      if (pathname === '/ready') {
        return new Response(JSON.stringify({ status: 'starting' }), { status: 503 });
      }
      return new Response('test_runs_started_total 1', { status: 200 });
    };
    await assert.rejects(
      () => runOperatorRunbookExercise({
        baseUrl: 'http://127.0.0.1:9',
        releaseId: 'rel-ready-fail',
        environment: 'staging',
        out: '/tmp/runbook-ready-fail.json',
      }),
      /ready/,
    );
  });

  it('accepts metrics when response text includes test_runs_started_total', async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === '/health') {
        return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
      }
      if (pathname === '/ready') {
        return new Response(JSON.stringify({ status: 'ready' }), { status: 200 });
      }
      if (pathname === '/metrics') {
        return new Response('test_runs_started_total 42\n', { status: 200 });
      }
      return new Response('not found', { status: 404 });
    };

    const result = await runOperatorRunbookExercise({
      baseUrl: 'http://127.0.0.1:9',
      releaseId: 'rel-metrics-ok',
      environment: 'staging',
      out: '/tmp/runbook-metrics-ok.json',
    });
    assert.equal(result.steps.find((s) => s.step === 'metrics')?.ok, true);
  });
});

describe('OIDC staging login drill edge cases', () => {
  let originalFetch;

  afterEach(() => {
    if (originalFetch) globalThis.fetch = originalFetch;
  });

  it('fails manifest validation when positive role probes return 401', async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init = {}) => {
      const pathname = new URL(url).pathname;
      const auth = init.headers?.authorization ?? '';
      if (pathname === '/v1/checks' && auth.startsWith('Bearer ')) {
        return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
      }
      if (pathname === '/v1/checks') {
        return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
      }
      if (pathname === '/v1/target-groups') {
        return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
      }
      return new Response('not found', { status: 404 });
    };

    await assert.rejects(
      () => runLiveOidcStagingLogin({
        baseUrl: 'https://staging.example.test',
        releaseId: 'rel-oidc-fail',
        environment: 'staging',
        out: '/tmp/oidc-fail.json',
      }),
      /OIDC staging login evidence incomplete/,
    );
  });

  it('marks header_only_negative passed when API returns 401 without bearer', async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init = {}) => {
      const pathname = new URL(url).pathname;
      const auth = init.headers?.authorization ?? '';
      if (pathname === '/v1/checks' && !auth) {
        return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
      }
      if (pathname === '/v1/checks' && auth === 'Bearer invalid.token.value') {
        return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
      }
      if (pathname === '/v1/checks' || pathname === '/v1/target-groups') {
        return new Response(JSON.stringify({ items: [] }), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    };

    const result = await runLiveOidcStagingLogin({
      baseUrl: 'https://staging.example.test',
      releaseId: 'rel-oidc-partial',
      environment: 'staging',
      out: '/tmp/oidc-partial.json',
    });
    const headerOnly = result.evidence.scenarios.find((s) => s.scenario_id === 'header_only_negative');
    const invalidToken = result.evidence.scenarios.find((s) => s.scenario_id === 'invalid_token_rejected');
    assert.equal(headerOnly?.status, 'passed');
    assert.equal(invalidToken?.status, 'passed');
  });
});