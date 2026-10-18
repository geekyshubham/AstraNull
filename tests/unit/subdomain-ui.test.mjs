import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';
import { fetchSubdomainsFromSource, fetchVirusTotalUiSubdomains } from '../../src/lib/subdomainEnumeration.mjs';
import { runVirusTotalUiSubdomains } from '../../src/lib/virusTotalUiSubdomains.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';

test('VirusTotal UI transport pagination, proxy, retries, partial results and limits (Python)', () => {
  execFileSync('python3', ['tests/unit/virustotal_subdomains_test.py'], {
    timeout: 10_000, stdio: 'pipe', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
});

test('UI source normalizes, filters, deduplicates and caps helper results', async () => {
  let input; let options;
  const result = await fetchSubdomainsFromSource('example.com', {
    configured: true, source: 'virustotal_ui', maxResults: 2, proxyUrl: 'http://private:credential@proxy:10000',
    pythonExecutable: '/path/to/python',
  }, { runUiFn: async (value, opts) => {
    input = value; options = opts;
    return { hostnames: ['B.Example.com.', '*.example.com', 'a.example.com', 'b.example.com', 'example.com', 'other.net',
      'example.com.evil.net', 'c.example.com'], pages: 1, reported_total: 8, truncated: false, stop_reason: null };
  } });
  assert.deepEqual(result.hostnames, ['a.example.com', 'b.example.com']);
  assert.equal(result.source, 'virustotal_ui');
  assert.equal(result.stop_reason, 'max_results');
  assert.equal(input.proxyUrl, 'http://private:credential@proxy:10000');
  assert.equal(input.maxResults, 2);
  assert.equal(options.pythonExecutable, '/path/to/python');
  assert.ok(!JSON.stringify(result).includes('credential'));
});

test('UI transport failures are typed and never expose helper error strings', async () => {
  for (const [error, code, status] of [
    ['subdomain_source_not_configured', 'subdomain_source_not_configured', 503],
    ['subdomain_source_rate_limited', 'subdomain_source_rate_limited', 429],
    ['subdomain_source_auth_failed', 'subdomain_source_auth_failed', 502],
    ['proxy password private-credential', 'subdomain_source_failed', 502],
  ]) {
    await assert.rejects(fetchVirusTotalUiSubdomains('example.com', { runUiFn: async () => ({ error }) }),
      (failure) => failure.code === code && failure.status === status && !failure.message.includes('private-credential'));
  }
  await assert.rejects(fetchVirusTotalUiSubdomains('example.com', { runUiFn: async () => ({ hostnames: [] }) }),
    (error) => error.code === 'subdomain_source_failed');
  assert.deepEqual(await runVirusTotalUiSubdomains({ domain: 'example.com' }, { pythonExecutable: '/nonexistent/python' }),
    { error: 'subdomain_source_not_configured' });
});

test('runtime wires explicit UI source, proxy and Python override without needing an API key', () => {
  const config = loadRuntimeConfig({ NODE_ENV: 'test', ASTRANULL_SUBDOMAIN_SOURCE: 'virustotal_ui',
    ASTRANULL_SUBDOMAIN_PROXY_URL: 'http://user:pass@proxy:10000', ASTRANULL_SUBDOMAIN_PYTHON: '/venv/bin/python' }).subdomainDiscovery;
  assert.equal(config.source, 'virustotal_ui');
  assert.equal(config.configured, true);
  assert.equal(config.proxyUrl, 'http://user:pass@proxy:10000');
  assert.equal(config.pythonExecutable, '/venv/bin/python');
});
