import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fetchSubdomainsFromSource, fetchVirusTotalUiSubdomains } from '../../src/lib/subdomainEnumeration.mjs';
import { runVirusTotalUiSubdomains } from '../../src/lib/virusTotalUiSubdomains.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { enumerateTargetSubdomains } from '../../src/services/subdomains.mjs';

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
    ASTRANULL_SUBDOMAIN_PROXY_URL: 'http://user:pass@proxy:10000', ASTRANULL_SUBDOMAIN_PYTHON: '/venv/bin/python',
    ASTRANULL_SUBDOMAIN_MAX_RESULTS: '200' }).subdomainDiscovery;
  assert.equal(config.source, 'virustotal_ui');
  assert.equal(config.configured, true);
  assert.equal(config.proxyUrl, 'http://user:pass@proxy:10000');
  assert.equal(config.pythonExecutable, '/venv/bin/python');
  assert.equal(config.maxResults, 0, 'legacy deployment settings must not truncate the UI source');
});

test('UI source retains all normalized hosts beyond the old 1000 result ceiling by default', async () => {
  const hostnames = Array.from({ length: 2401 }, (_, i) => `h${i}.example.com`);
  const result = await fetchVirusTotalUiSubdomains('example.com', { runUiFn: async (input) => {
    assert.equal(input.maxResults, 0);
    return { hostnames, pages: 61, reported_total: 2401, truncated: false, stop_reason: null };
  } });
  assert.equal(result.hostnames.length, 2401);
  assert.equal(result.truncated, false);
});

test('helper inactivity is bounded and cancellation terminates the child process', { timeout: 5000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'astranull-subdomain-child-'));
  const executable = join(directory, 'python');
  try {
    writeFileSync(executable, `#!/usr/bin/env node
process.stdin.resume();
setInterval(() => {}, 10000);
`, { mode: 0o700 });
    const idle = await runVirusTotalUiSubdomains({ domain: 'example.com' }, { pythonExecutable: executable, idleTimeoutMs: 500 });
    assert.equal(idle.error, 'subdomain_source_unreachable');
    writeFileSync(executable, `#!/usr/bin/env node
process.stdin.resume();
console.log(JSON.stringify({type:'progress',progress:{phase:'fetching',pid:process.pid}}));
setInterval(() => {}, 10000);
`, { mode: 0o700 });
    const controller = new AbortController();
    let pid;
    const cancelled = await runVirusTotalUiSubdomains({ domain: 'example.com' }, {
      pythonExecutable: executable, signal: controller.signal,
      onProgress: progress => { pid = progress.pid; controller.abort(); },
    });
    assert.equal(cancelled.error, 'subdomain_discovery_cancelled');
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  } finally { unlinkSync(executable); rmdirSync(directory); }
});

test('cancelling during declaration preserves committed hosts and audits the partial outcome', async () => {
  const controller = new AbortController();
  const parent = { id: 'parent', tenant_id: 'tenant', target_group_id: 'group', kind: 'fqdn', value: 'example.com' };
  let created = 0; let audit;
  const result = await enumerateTargetSubdomains({ tenantId: 'tenant', userId: 'user', role: 'admin' }, parent.id, {
    readTarget: async () => parent,
    readCohort: async () => ({ items: [parent] }),
    config: { configured: true, source: 'virustotal_ui' },
    runUiFn: async () => ({ hostnames: ['a.example.com', 'b.example.com', 'c.example.com'], pages: 1,
      reported_total: 3, truncated: false, stop_reason: null }),
    createTarget: async () => { created += 1; controller.abort(); return { id: 'child', target_group_id: 'group' }; },
    recordAudit: async entry => { audit = entry; }, signal: controller.signal,
  });
  assert.equal(created, 1);
  assert.equal(result.created.length, 1);
  assert.equal(result.already_declared, 0);
  assert.equal(result.truncated, true);
  assert.equal(result.stop_reason, 'cancelled');
  assert.equal(audit.metadata.cancelled, true);
  assert.equal(audit.metadata.created_count, 1);
});
