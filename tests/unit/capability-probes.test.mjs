import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { describe, it } from 'node:test';
import { isLiveCapabilityProbeAuthorized } from '../../src/lib/capabilityProbeAuth.mjs';
import {
  MAX_DNS_TCP_RESPONSE_BYTES,
  accumulateDnsTcpResponse,
  buildAxfrDnsMessage,
  encodeDnsQName,
  frameDnsTcpMessage,
  parseDnsResponseHeader,
} from '../../src/lib/dnsTcpWire.mjs';
import {
  BOUNDED_SUBDOMAIN_PREFIXES,
  CAPABILITY_PROBE_DISPATCH,
  probeApiSurfaceScan,
  probeAxfrLeak,
  probeBotChallenge,
  probeCacheAbuse,
  probeCorsPosture,
  probeDnsFailoverPosture,
  probeDnssecPosture,
  probeGraphqlPosture,
  probeHostSniBypass,
  probeHeaderSizeBoundary,
  probeHttp2FrameBehavior,
  probeHttp3ControlStream,
  probeHttpMethodMatrix,
  probeOpenRecursion,
  probeOriginLeakScan,
  probePortScanBounded,
  probeRateLimitSequence,
  probeSlowHeaderTimeout,
  probeTlsAudit,
  probeWafEnforcement,
  probeOutsideInWafScan,
  probeWafClassMarker,
  probeDelegatedL7ResourcePosture,
  executeCapabilityProbe,
} from '../../src/lib/capabilityProbes.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { BENIGN_CLASS_MARKERS } from '../../src/lib/outsideInWafScanner.mjs';

function job(overrides = {}) {
  return {
    constraints: { timeout_ms: 1000, max_requests: 15 },
    probe_profile: { kind: 'origin_leak_scan' },
    target: { kind: 'fqdn', value: 'shop.example.test' },
    ...overrides,
  };
}

function httpResponse(status, headers = {}, body = '') {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]),
  );
  const bytes = new TextEncoder().encode(body);
  return {
    status,
    headers: { get: (name) => normalized[String(name).toLowerCase()] ?? null },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }),
  };
}

describe('capability probes P0/P1', () => {
  it('origin leak scan stops at constraints max_requests budget', async () => {
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
    }), {
      resolve4Fn: async () => [],
      resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 404, headers: { get: () => null } }),
    });
    assert.equal(outcome.requests_sent, 4);
    assert.equal(outcome.metadata.subdomains_scanned.length, 1);
    assert.ok(outcome.metadata.subdomains_scanned.length < BOUNDED_SUBDOMAIN_PREFIXES.length);
  });

  it('origin leak max_requests=1 fails before apex A, apex AAAA, or edge HEAD', async () => {
    const operations = [];
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      probe_profile: { kind: 'origin_leak_scan', max_requests: 1 },
    }), {
      resolve4Fn: async () => { operations.push('A'); return []; },
      resolve6Fn: async () => { operations.push('AAAA'); return []; },
      fetchFn: async () => {
        operations.push('HEAD');
        return { status: 404, headers: { get: () => null } };
      },
    });

    assert.deepEqual(operations, []);
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'signed_request_budget_below_mandatory_floor');
    assert.equal(outcome.metadata.required_requests, 3);
    assert.equal(outcome.requests_sent, 0);
  });

  for (const family of ['A', 'AAAA']) {
    it(`origin leak normalizes transient apex ${family} resolver failure to error`, async () => {
      let fetchCalls = 0;
      const failure = Object.assign(new Error('temporary resolver failure'), { code: 'EAI_AGAIN' });
      const outcome = await probeOriginLeakScan(job(), {
        resolve4Fn: async () => {
          if (family === 'A') throw failure;
          return [];
        },
        resolve6Fn: async () => {
          if (family === 'AAAA') throw failure;
          return [];
        },
        fetchFn: async () => { fetchCalls += 1; return httpResponse(200); },
      });

      assert.equal(outcome.external_result, 'error');
      assert.equal(outcome.metadata.error_class, 'EAI_AGAIN');
      assert.equal(outcome.requests_sent, family === 'A' ? 1 : 2);
      assert.equal(fetchCalls, 0);
    });
  }

  it('origin leak normalizes a transient subdomain resolver failure instead of grading posture', async () => {
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
    }), {
      resolve4Fn: async (host) => {
        if (host === 'www.shop.example.test') {
          throw Object.assign(new Error('temporary resolver failure'), { code: 'EAI_AGAIN' });
        }
        return [];
      },
      resolve6Fn: async () => [],
      fetchFn: async () => httpResponse(200),
    });

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'EAI_AGAIN');
    assert.equal(outcome.requests_sent, 4);
    assert.ok(outcome.metadata.subdomains_scanned.includes('www.shop.example.test'));
  });

  it('origin leak preserves operation-budget and deadline resolver semantics', async () => {
    await assert.rejects(
      () => probeOriginLeakScan(job(), {
        resolve4Fn: async () => {
          throw Object.assign(new Error('budget exhausted'), {
            code: 'signed_operation_budget_exceeded',
          });
        },
        resolve6Fn: async () => [],
        fetchFn: async () => httpResponse(200),
      }),
      (error) => error?.code === 'signed_operation_budget_exceeded',
    );

    const deadline = await probeOriginLeakScan(job(), {
      resolve4Fn: async () => {
        throw Object.assign(new Error('deadline'), {
          name: 'AbortError',
          code: 'probe_job_deadline_exceeded',
        });
      },
      resolve6Fn: async () => [],
      fetchFn: async () => httpResponse(200),
    });
    assert.equal(deadline.external_result, 'timeout');
    assert.equal(deadline.metadata.error_class, 'probe_job_deadline_exceeded');
    assert.equal(deadline.requests_sent, 1);
  });

  it('origin leak scan reports leak signals from subdomain divergence', async () => {
    const outcome = await probeOriginLeakScan(job(), {
      resolve4Fn: async (host) => {
        if (host === 'shop.example.test') return ['203.0.113.10'];
        if (host === 'origin.shop.example.test') return ['198.51.100.5'];
        return [];
      },
      resolve6Fn: async () => ['2001:db8::1'],
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.leak_signals.includes('ipv6_present'), false);
    assert.ok(outcome.metadata.leak_signals.some((s) => s.startsWith('subdomain_origin_divergence:')));
  });

  it('origin leak scan does not flag normal dual-stack DNS as a leak', async () => {
    const outcome = await probeOriginLeakScan(job(), {
      resolve4Fn: async (host) => (host === 'shop.example.test' ? ['203.0.113.10'] : []),
      resolve6Fn: async () => ['2001:db8::1'],
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.deepEqual(outcome.metadata.leak_signals, []);
    assert.deepEqual(outcome.metadata.ipv6_addrs, ['2001:db8::1']);
  });

  it('origin leak scan does not flag subdomains that resolve to the apex edge IP', async () => {
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
    }), {
      resolve4Fn: async (host) => {
        if (host === 'shop.example.test') return ['203.0.113.10'];
        if (host === 'www.shop.example.test') return ['203.0.113.10'];
        return [];
      },
      resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.deepEqual(outcome.metadata.leak_signals, []);
    assert.equal(outcome.metadata.subdomains_scanned.length, 1);
  });

  it('origin leak scan default budget covers the full bounded prefix list', async () => {
    const outcome = await probeOriginLeakScan(job(), {
      resolve4Fn: async () => [],
      resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 404, headers: { get: () => null } }),
    });
    assert.equal(outcome.requests_sent, 15);
    assert.equal(outcome.metadata.subdomains_scanned.length, BOUNDED_SUBDOMAIN_PREFIXES.length);
  });

  it('delegated transport refuses retargeting and unsafe HTTP shapes before egress', async () => {
    let reservations = 0;
    let networkCalls = 0;
    const base = job({
      target: { kind: 'url', value: 'https://edge.example.test/signed/path' },
      constraints: { max_requests: 1, timeout_ms: 1000 },
    });

    const retargeted = await probeWafClassMarker({
      ...base,
      probe_profile: { kind: 'waf_class_marker_probe', marker_class: 'ssrf', max_requests: 1 },
    }, {
      signedJobVerified: true,
      recordProbeLogicalAttempt: () => { reservations += 1; },
      fetchFn: async () => { networkCalls += 1; return httpResponse(200); },
      wafClassProbeFn: async ({ fetchFn }) => {
        try { await fetchFn('https://attacker.invalid/'); } catch {}
        return { posture: 'inconclusive', marker_results: [], requests_sent: 99 };
      },
    });
    assert.equal(retargeted.external_result, 'error');
    assert.equal(retargeted.metadata.error_class, 'delegated_target_mismatch');
    assert.equal(retargeted.requests_sent, 0);

    for (const unsafeInit of [
      { method: 'POST', headers: { connection: 'close' }, body: 'inert' },
      { method: 'GET', body: '' },
      { method: 'POST', body: 'x'.repeat(4097) },
    ]) {
      const refused = await probeDelegatedL7ResourcePosture({
        ...base,
        probe_profile: {
          kind: 'l7_resource_posture_probe',
          marker_class: 'declared_content_encoding',
          max_requests: 1,
        },
      }, {
        signedJobVerified: true,
        recordProbeLogicalAttempt: () => { reservations += 1; },
        fetchFn: async () => { networkCalls += 1; return httpResponse(200); },
        l7ResourceProbeFn: async (_job, { requestFn }) => {
          try {
            await requestFn('https://edge.example.test/signed/path', unsafeInit);
          } catch {}
          return { external_result: 'connected', metadata: {}, requests_sent: 99 };
        },
      });
      assert.equal(refused.external_result, 'error');
      assert.equal(refused.metadata.error_class, 'unsafe_delegated_http_request');
      assert.equal(refused.requests_sent, 0);
    }
    assert.equal(reservations, 0);
    assert.equal(networkCalls, 0);
  });

  it('host/SNI bypass derives direct IP and URL from declared http target', async () => {
    const outcome = await probeHostSniBypass(
      job({
        target: { kind: 'url', value: 'http://198.51.100.7:8080/health' },
        probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.example.test' },
      }),
      {
        fetchFn: async (url, init) => {
          assert.equal(url, 'http://198.51.100.7:8080/health');
          assert.equal(init.headers.Host, 'edge.example.test');
          return { status: 200, headers: { get: () => null } };
        },
      },
    );
    assert.equal(outcome.metadata.bypass_signal, true);
    assert.equal(outcome.metadata.direct_ip, '198.51.100.7');
  });

  it('host/SNI bypass reports missing direct IP before live probing', async () => {
    const outcome = await probeHostSniBypass(
      job({
        target: { kind: 'fqdn', value: 'edge.example.test' },
        probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.example.test' },
      }),
      {
        fetchFn: async () => {
          throw new Error('should not execute without direct IP');
        },
      },
    );
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'missing_direct_ip_or_host');
    assert.equal(outcome.requests_sent, 0);
  });

  it('host/SNI bypass preserves URL port and path when direct IP comes from metadata', async () => {
    let captured = null;
    const outcome = await probeHostSniBypass(
      job({
        target: {
          kind: 'url',
          value: 'https://edge.example.test:8443/health?probe=1',
          metadata: { direct_origin_ip: '198.51.100.7' },
        },
        probe_profile: { kind: 'host_sni_bypass' },
      }),
      {
        httpsRequestFn: (opts, cb) => {
          captured = opts;
          return {
            on() { return this; },
            end() {
              cb({ statusCode: 200, headers: {}, resume() {} });
            },
          };
        },
      },
    );
    assert.equal(captured.host, '198.51.100.7');
    assert.equal(captured.servername, 'edge.example.test');
    assert.equal(captured.port, 8443);
    assert.equal(captured.path, '/health?probe=1');
    assert.equal(captured.headers.Host, 'edge.example.test:8443');
    assert.equal(outcome.metadata.bypass_signal, true);
  });

  it('host/SNI bypass detects direct IP reachability via injectable fetchFn', async () => {
    const outcome = await probeHostSniBypass(
      job({
        probe_profile: {
          kind: 'host_sni_bypass',
          protected_host: 'edge.example.test',
          direct_ip: '198.51.100.7',
        },
      }),
      {
        fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.bypass_signal, true);
  });

  it('host/SNI bypass uses HTTPS with TLS SNI when no fetchFn is injected', async () => {
    let captured = null;
    const outcome = await probeHostSniBypass(
      job({
        probe_profile: {
          kind: 'host_sni_bypass',
          protected_host: 'edge.example.test',
          direct_ip: '198.51.100.7',
        },
      }),
      {
        httpsRequestFn: (opts, cb) => {
          captured = opts;
          return {
            on() { return this; },
            end() {
              cb({ statusCode: 200, headers: {}, resume() {} });
            },
          };
        },
      },
    );
    assert.equal(captured.host, '198.51.100.7');
    assert.equal(captured.servername, 'edge.example.test');
    assert.equal(outcome.metadata.bypass_signal, true);
  });

  it('port scan respects max_requests from probe profile', async () => {
    const probedPorts = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 5000 },
        target: { value: '10.0.0.5' },
        probe_profile: {
          kind: 'port_scan_bounded',
          max_requests: 3,
          ports: [22, 443, 80, 8080, 9999],
        },
      }),
      {
        destinationPolicy: { allowPrivate: true },
        connectFn: ({ port }, cb) => {
          probedPorts.push(port);
          const socket = {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
          return socket;
        },
      },
    );
    assert.deepEqual(probedPorts, [22, 443, 80]);
    assert.equal(outcome.requests_sent, 3);
  });

  it('port scan preserves IPv6 literal IP targets', async () => {
    let resolved = false;
    const probed = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 1000, max_requests: 1 },
        target: { kind: 'ip', value: '2001:db8::1' },
        probe_profile: { kind: 'port_scan_bounded', ports: [443] },
      }),
      {
        resolve4Fn: async () => {
          resolved = true;
          return [];
        },
        connectFn: ({ host, port }) => {
          probed.push({ host, port });
          return {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
        },
      },
    );
    assert.equal(resolved, false);
    assert.deepEqual(probed, [{ host: '2001:db8::1', port: 443 }]);
    assert.equal(outcome.requests_sent, 1);
  });

  it('port scan uses the full port budget for FQDN targets', async () => {
    const probedPorts = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 10000, max_requests: 15 },
        target: { kind: 'fqdn', value: 'scan.example.test' },
        probe_profile: { kind: 'port_scan_bounded', max_requests: 15 },
      }),
      {
        resolve4Fn: async () => ['203.0.113.55'],
        connectFn: ({ port }) => {
          probedPorts.push(port);
          return {
            once(event, handler) {
              if (event === 'error') handler({ code: 'ECONNREFUSED' });
            },
            destroy() {},
          };
        },
      },
    );
    assert.equal(probedPorts.length, 15);
    assert.equal(probedPorts.at(-1), 8443);
    assert.equal(outcome.requests_sent, 15);
  });

  it('port scan bounded reports risky admin ports', async () => {
    const outcome = await probePortScanBounded(
      job({
        target: { value: '10.0.0.5' },
        probe_profile: { kind: 'port_scan_bounded', ports: [22, 443, 9999] },
      }),
      {
        destinationPolicy: { allowPrivate: true },
        connectFn: ({ port }, cb) => {
          const socket = {
            once(event, handler) {
              if (event === 'connect') setImmediate(() => handler());
            },
            end() {},
            destroy() {},
          };
          if (port === 22) return socket;
          const errSocket = {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
          return errSocket;
        },
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.deepEqual(outcome.metadata.open_ports, [22]);
    assert.deepEqual(outcome.metadata.risky_admin_ports_open, [22]);
  });

  it('rate limit sequence detects throttling', async () => {
    let n = 0;
    const outcome = await probeRateLimitSequence(
      job({
        target: { value: 'https://login.example.test/signin' },
        probe_profile: { kind: 'rate_limit_sequence', max_requests: 3 },
      }),
      {
        fetchFn: async () => {
          n += 1;
          return { status: n >= 2 ? 429 : 200, headers: { get: () => null } };
        },
      },
    );
    assert.equal(outcome.metadata.throttled, true);
    assert.equal(outcome.external_result, 'blocked');
  });

  it('rate limit sequence returns error instead of an exposure verdict on transport failure', async () => {
    let attempts = 0;
    const outcome = await probeRateLimitSequence(job({
      constraints: { max_requests: 5, timeout_ms: 1000 },
      target: { value: 'https://post.example.test/submit' },
      probe_profile: {
        kind: 'rate_limit_sequence',
        max_requests: 5,
        http_method: 'POST',
        nonce_hash_only: true,
      },
    }), {
      fetchFn: async () => {
        attempts += 1;
        throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
      },
    });

    assert.equal(attempts, 1);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'ECONNREFUSED');
  });

  it('D-04 rate-limit checks emit distinguishable declared endpoint evidence', async () => {
    const urls = [];
    const fetchFn = async (url) => {
      urls.push(url);
      return httpResponse(200);
    };
    const search = await probeRateLimitSequence(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/original' },
      probe_profile: {
        kind: 'rate_limit_sequence',
        max_requests: 1,
        probe_path: '/catalog/search',
        http_method: 'GET',
      },
    }), { fetchFn });
    const signup = await probeRateLimitSequence(job({
      nonce_hash: 'sha256:signup-marker',
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/original' },
      probe_profile: {
        kind: 'rate_limit_sequence',
        max_requests: 1,
        probe_path: '/account/signup-probe',
        http_method: 'POST',
        nonce_hash_only: true,
      },
    }), { fetchFn });

    assert.equal(search.metadata.probe_path, '/catalog/search');
    assert.equal(search.metadata.http_method, 'GET');
    assert.equal(signup.metadata.probe_path, '/account/signup-probe');
    assert.equal(signup.metadata.http_method, 'POST');
    assert.notEqual(search.metadata.probe_path, signup.metadata.probe_path);
    assert.deepEqual(urls, [
      'https://app.example.test/catalog/search',
      'https://app.example.test/account/signup-probe',
    ]);
  });

  it('rate-limit POST without nonce-hash-only marker fails closed before fetch', async () => {
    let attempts = 0;
    const outcome = await probeRateLimitSequence(job({
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: {
        kind: 'rate_limit_sequence',
        max_requests: 5,
        probe_path: '/oauth/token-probe',
        http_method: 'POST',
      },
    }), {
      fetchFn: async () => { attempts += 1; return httpResponse(200); },
    });

    assert.equal(attempts, 0);
    assert.equal(outcome.requests_sent, 0);
    assert.equal(outcome.metadata.error_class, 'unsafe_post_profile');
  });

  it('rejects a forged DELETE rate-limit profile before fetch', async () => {
    let attempts = 0;
    const outcome = await probeRateLimitSequence(job({
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: {
        kind: 'rate_limit_sequence',
        max_requests: 1,
        probe_path: '/account',
        http_method: 'DELETE',
      },
    }), {
      fetchFn: async () => { attempts += 1; return httpResponse(200); },
    });

    assert.equal(attempts, 0);
    assert.equal(outcome.requests_sent, 0);
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'unsafe_http_method');
  });

  it('HTTP method posture sends only HEAD/OPTIONS and reports advertised unsafe methods', async () => {
    const calls = [];
    const outcome = await probeHttpMethodMatrix(job({
      nonce_hash: 'sha256:method-marker',
      constraints: { max_requests: 2, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: { kind: 'http_method_matrix', max_requests: 2, probe_path: '/method-policy' },
    }), {
      fetchFn: async (_url, init) => {
        calls.push(init.method);
        return init.method === 'OPTIONS'
          ? httpResponse(204, { allow: 'GET, HEAD, OPTIONS, TRACE' })
          : httpResponse(200);
      },
    });

    assert.deepEqual(calls, ['HEAD', 'OPTIONS']);
    assert.equal(outcome.requests_sent, 2);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.trace_advertised, true);
    assert.equal(outcome.metadata.trace_enabled, null);
    assert.deepEqual(outcome.metadata.unsafe_methods_advertised, ['TRACE']);
    assert.equal(outcome.metadata.unsafe_methods_executed, false);
  });

  it('HTTP method posture stays inconclusive without an Allow policy and respects its cap', async () => {
    let attempts = 0;
    const complete = await probeHttpMethodMatrix(job({
      constraints: { max_requests: 2, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: { kind: 'http_method_matrix', max_requests: 2 },
    }), {
      fetchFn: async () => { attempts += 1; return httpResponse(405); },
    });
    assert.deepEqual(complete.metadata.methods_blocked, ['HEAD', 'OPTIONS']);
    assert.deepEqual(complete.metadata.methods_allowed, []);
    assert.equal(complete.external_result, 'error');
    assert.equal(attempts, 2);

    attempts = 0;
    const bounded = await probeHttpMethodMatrix(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: { kind: 'http_method_matrix', max_requests: 2 },
    }), {
      fetchFn: async () => { attempts += 1; return httpResponse(405); },
    });
    assert.equal(attempts, 1);
    assert.equal(bounded.requests_sent, 1);
  });

  it('header-size boundary sends the configured header and recognizes 431 enforcement', async () => {
    const headerLengths = [];
    const outcome = await probeHeaderSizeBoundary(job({
      constraints: { max_requests: 2, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: { kind: 'header_size_probe', max_requests: 2, oversize_header_bytes: 8_192 },
    }), {
      fetchFn: async (_url, init) => {
        headerLengths.push(init.headers['x-astranull-boundary']?.length ?? 0);
        return httpResponse(headerLengths.length === 1 ? 200 : 431);
      },
    });

    assert.deepEqual(headerLengths, [0, 8_192]);
    assert.equal(outcome.metadata.oversize_status, 431);
    assert.equal(outcome.metadata.oversize_bytes, 8_192);
    assert.equal(outcome.metadata.boundary_enforced, true);
  });

  it('header-size boundary returns error instead of exposed when a request fails', async () => {
    const outcome = await probeHeaderSizeBoundary(job({
      constraints: { max_requests: 2, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://app.example.test/' },
      probe_profile: { kind: 'header_size_probe', max_requests: 2 },
    }), {
      fetchFn: async () => {
        throw Object.assign(new Error('reset'), { code: 'ECONNRESET' });
      },
    });

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'ECONNRESET');
    assert.equal(outcome.metadata.comparison_complete, false);
  });

  it('slow-header probe opens one connection and always closes it after server close', async () => {
    let connections = 0;
    let destroyCount = 0;
    const outcome = await probeSlowHeaderTimeout(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.20/slow' },
      probe_profile: { kind: 'slow_header_probe', max_requests: 1, probe_path: '/slow' },
    }), {
      connectFn: () => {
        connections += 1;
        const socket = new EventEmitter();
        socket.write = () => queueMicrotask(() => socket.emit('close'));
        socket.destroy = () => { destroyCount += 1; };
        queueMicrotask(() => socket.emit('secureConnect'));
        return socket;
      },
    });

    assert.equal(connections, 1);
    assert.equal(destroyCount, 1);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.metadata.connection_closed_by_server, true);
    assert.equal(outcome.metadata.timeout_enforced, true);
  });

  it('slow-header probe closes its single connection when partial write throws', async () => {
    let connections = 0;
    let destroyCount = 0;
    const outcome = await probeSlowHeaderTimeout(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.20/slow' },
      probe_profile: { kind: 'slow_header_probe', max_requests: 1, probe_path: '/slow' },
    }), {
      connectFn: () => {
        connections += 1;
        const socket = new EventEmitter();
        socket.write = () => { throw Object.assign(new Error('write failed'), { code: 'EWRITE' }); };
        socket.destroy = () => { destroyCount += 1; };
        queueMicrotask(() => socket.emit('secureConnect'));
        return socket;
      },
    });

    assert.equal(connections, 1);
    assert.equal(destroyCount, 1);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.metadata.error_class, 'EWRITE');
    assert.equal(outcome.external_result, 'error');
  });

  it('slow-header connection errors cannot masquerade as timeout enforcement', async () => {
    const outcome = await probeSlowHeaderTimeout(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.20/slow' },
      probe_profile: { kind: 'slow_header_probe', max_requests: 1 },
    }), {
      connectFn: () => {
        const socket = new EventEmitter();
        socket.destroy = () => {};
        queueMicrotask(() => socket.emit('error', Object.assign(new Error('refused'), {
          code: 'ECONNREFUSED',
        })));
        return socket;
      },
    });

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'ECONNREFUSED');
    assert.equal(outcome.metadata.timeout_enforced, false);
  });

  it('HTTP/2 frame behavior sends exactly one RST_STREAM', async () => {
    let resetCount = 0;
    const session = new EventEmitter();
    session.alpnProtocol = 'h2';
    session.ping = (_payload, callback) => queueMicrotask(() => callback(null, 2));
    session.request = () => {
      const stream = new EventEmitter();
      stream.close = () => { resetCount += 1; };
      return stream;
    };
    session.close = () => {};
    session.destroy = () => {};
    const outcomePromise = probeHttp2FrameBehavior(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.21/h2' },
      probe_profile: { kind: 'http2_frame_probe', max_requests: 4, probe_path: '/h2' },
    }), {
      signedJobVerified: true,
      http2ConnectFn: () => {
        queueMicrotask(() => {
          session.emit('connect');
          session.emit('remoteSettings', {
            maxConcurrentStreams: 100,
            maxHeaderListSize: 16_384,
            enablePush: false,
          });
        });
        return session;
      },
    });
    const outcome = await outcomePromise;

    assert.equal(resetCount, 1);
    // Three real initializers: connect, ping, single reset stream. Reading the already-received
    // SETTINGS header bound is not a network operation and must not be attested as one.
    assert.equal(outcome.requests_sent, 3);
    assert.equal(outcome.metadata.reset_accepted, true);
    assert.equal(outcome.metadata.continuation_bound_advertised, true);
  });

  it('HTTP/2 SETTINGS-only HPACK assertion grades negotiated bounds without extra frames', async () => {
    const session = new EventEmitter();
    session.alpnProtocol = 'h2';
    session.close = () => {};
    session.destroy = () => {};
    const outcomePromise = probeHttp2FrameBehavior(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.21/h2' },
      probe_profile: {
        kind: 'http2_frame_probe',
        max_requests: 1,
        settings_assertion: 'hpack_limits',
      },
    }), {
      signedJobVerified: true,
      http2ConnectFn: () => {
        queueMicrotask(() => {
          session.emit('connect');
          session.emit('remoteSettings', {
            headerTableSize: 4096,
            maxHeaderListSize: 16_384,
          });
        });
        return session;
      },
    });
    const outcome = await outcomePromise;

    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.settings_assertion, 'hpack_limits');
    assert.equal(outcome.metadata.header_table_size, 4096);
    assert.equal(outcome.metadata.max_header_list_size, 16_384);
    assert.equal(outcome.metadata.hpack_limits_advertised, true);
    assert.equal(outcome.metadata.ping_rtt_ms, null);
    assert.equal(outcome.metadata.reset_accepted, null);
  });

  it('HTTP/2 frame behavior reports a non-h2 target cleanly', async () => {
    const session = new EventEmitter();
    session.alpnProtocol = 'http/1.1';
    session.close = () => {};
    session.destroy = () => {};
    const outcomePromise = probeHttp2FrameBehavior(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.22/' },
      probe_profile: { kind: 'http2_frame_probe', max_requests: 4 },
    }), {
      signedJobVerified: true,
      http2ConnectFn: () => {
        queueMicrotask(() => session.emit('connect'));
        return session;
      },
    });
    const outcome = await outcomePromise;

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'http2_not_negotiated');
    assert.equal(outcome.requests_sent, 1);
  });

  it('HTTP/3 control probe truthfully performs one HEAD Alt-Svc observation only', async () => {
    const operations = [];
    const methods = [];
    let socketCalls = 0;
    const outcome = await probeHttp3ControlStream(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://203.0.113.25/h3' },
      probe_profile: { kind: 'http3_control_probe', max_requests: 1 },
    }), {
      recordProbeLogicalAttempt: (operation) => operations.push(operation),
      fetchFn: async (_url, init) => {
        methods.push(init.method);
        return httpResponse(200, { 'alt-svc': 'h3=":8443"' });
      },
      createSocket: () => { socketCalls += 1; throw new Error('must not create socket'); },
    });

    assert.deepEqual(methods, ['HEAD']);
    assert.deepEqual(operations, ['http']);
    assert.equal(socketCalls, 0);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.metadata.probe_kind, 'http3_control_probe');
    assert.equal(outcome.metadata.capability_scope, 'http3_alt_svc_observation_only');
    assert.equal(outcome.metadata.advertised_h3_port, 8443);
    assert.equal('control_stream_observed' in outcome.metadata, false);
    assert.equal('settings_observed' in outcome.metadata, false);
    assert.equal('udp_response_received' in outcome.metadata, false);
  });

  it('WAF inspection-limit variants reuse only the benign SQLi marker and detect fail-open', async () => {
    const calls = [];
    const executor = CAPABILITY_PROBE_DISPATCH.waf_inspection_limit_probe;
    const outcome = await executor(job({
      constraints: { max_requests: 6, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://waf.example.test/' },
      probe_profile: { kind: 'waf_inspection_limit_probe', max_requests: 6, probe_path: '/inspect' },
    }), {
      fetchFn: async (url, init) => {
        calls.push({ url, init });
        return httpResponse(calls.length === 1 || calls.length > 2 ? 403 : 200);
      },
    });

    assert.equal(calls.length, 5);
    assert.ok(calls.length <= 6);
    assert.equal(outcome.requests_sent, calls.length);
    for (const { url, init } of calls) {
      const wire = `${url} ${Object.values(init.headers ?? {}).join(' ')} ${init.body ?? ''}`;
      assert.ok(wire.includes(BENIGN_CLASS_MARKERS.sqli) || decodeURIComponent(wire).includes(BENIGN_CLASS_MARKERS.sqli));
      assert.equal(wire.includes(BENIGN_CLASS_MARKERS.xss), false);
      assert.equal(wire.includes(BENIGN_CLASS_MARKERS.path_traversal), false);
    }
    assert.equal(outcome.metadata.variants.length, 4);
    assert.equal(outcome.metadata.inspection_limit_bypass_suspected, true);
    assert.equal(outcome.metadata.fail_open_signal, true);
  });

  it('WAF inspection-limit probe never reports protection without a usable blocked baseline', async () => {
    const executor = CAPABILITY_PROBE_DISPATCH.waf_inspection_limit_probe;
    const unblockedBaseline = await executor(job({
      constraints: { max_requests: 2, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://waf.example.test/' },
      probe_profile: { kind: 'waf_inspection_limit_probe', max_requests: 2 },
    }), {
      fetchFn: async () => httpResponse(200),
    });
    assert.equal(unblockedBaseline.external_result, 'not_run');
    assert.equal(unblockedBaseline.metadata.comparison_complete, false);

    let attempts = 0;
    const failedBaseline = await executor(job({
      constraints: { max_requests: 6, timeout_ms: 1000 },
      target: { kind: 'url', value: 'https://waf.example.test/' },
      probe_profile: { kind: 'waf_inspection_limit_probe', max_requests: 6 },
    }), {
      fetchFn: async () => {
        attempts += 1;
        throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
      },
    });
    assert.equal(attempts, 1);
    assert.equal(failedBaseline.external_result, 'error');
    assert.equal(failedBaseline.metadata.error_class, 'ECONNREFUSED');
    assert.equal(failedBaseline.metadata.comparison_complete, false);
  });

  it('sequential requests consume only the remaining whole-job timeout', async () => {
    let attempts = 0;
    const outcome = await probeRateLimitSequence(
      job({
        constraints: { max_requests: 3, timeout_ms: 40 },
        target: { value: 'https://login.example.test/signin' },
        probe_profile: { kind: 'rate_limit_sequence', max_requests: 3, timeout_ms: 40 },
      }),
      {
        // Deliberately ignores AbortSignal: boundedFetch must race the shared deadline itself.
        fetchFn: async () => {
          attempts += 1;
          await new Promise((resolve) => setTimeout(resolve, 25));
          return { status: 200, headers: { get: () => null } };
        },
      },
    );

    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.error_class, 'probe_job_deadline_exceeded');
    assert.ok(attempts >= 1 && attempts <= 2, `attempts ${attempts}`);
    assert.equal(outcome.requests_sent, attempts);
    assert.ok(outcome.duration_ms >= 35, `duration ${outcome.duration_ms}ms`);
  });

  it('waf enforcement flags monitor-only leak', async () => {
    const outcome = await probeWafEnforcement(
      job({
        target: { value: 'https://app.example.test' },
        probe_profile: { kind: 'waf_enforcement_probe', marker: 'test-marker' },
      }),
      {
        fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
      },
    );
    assert.equal(outcome.metadata.monitor_only_leak, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('dnssec posture reports missing DNSSEC', async () => {
    const outcome = await probeDnssecPosture(job({
      probe_profile: { kind: 'dnssec_posture' },
    }), {
      resolveFn: async () => {
        throw new Error('ENODATA');
      },
    });
    assert.equal(outcome.metadata.dnssec_missing, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('DNS posture probes return error for transient resolver failures', async () => {
    const transient = (code) => Object.assign(new Error(code), { code });

    const dnssec = await probeDnssecPosture(job({
      probe_profile: { kind: 'dnssec_posture', max_requests: 2 },
    }), {
      resolveFn: async () => { throw transient('ESERVFAIL'); },
    });
    assert.equal(dnssec.external_result, 'error');
    assert.equal(dnssec.metadata.error_class, 'ESERVFAIL');
    assert.equal(dnssec.requests_sent, 1);

    const recursion = await probeOpenRecursion(job({
      target: { kind: 'ip', value: '8.8.8.8' },
      probe_profile: { kind: 'dns_open_recursion', max_requests: 1 },
    }), {
      resolve4ExternalFn: async () => { throw transient('EAI_AGAIN'); },
    });
    assert.equal(recursion.external_result, 'error');
    assert.equal(recursion.metadata.error_class, 'EAI_AGAIN');
    assert.equal(recursion.requests_sent, 1);

    const failover = await probeDnsFailoverPosture(job({
      probe_profile: { kind: 'dns_failover_posture', max_requests: 3 },
    }), {
      resolveNsFn: async () => { throw transient('ETIMEOUT'); },
    });
    assert.equal(failover.external_result, 'error');
    assert.equal(failover.metadata.error_class, 'ETIMEOUT');
    assert.equal(failover.requests_sent, 1);
  });

  it('DNS failover preserves authoritative negatives but not transient secondary failures', async () => {
    const authoritative = await probeDnsFailoverPosture(job({
      target: { kind: 'fqdn', value: 'shop.example.test' },
      probe_profile: {
        kind: 'dns_failover_posture',
        max_requests: 3,
        secondary_nameservers: ['shop.example.test'],
      },
    }), {
      resolveNsFn: async () => ['ns1.example.test', 'ns2.example.test'],
      resolve4Fn: async () => { throw Object.assign(new Error('no data'), { code: 'ENODATA' }); },
    });
    assert.equal(authoritative.external_result, 'connected');
    assert.equal(authoritative.metadata.secondary_results[0].reachable, false);

    const transient = await probeDnsFailoverPosture(job({
      target: { kind: 'fqdn', value: 'shop.example.test' },
      probe_profile: {
        kind: 'dns_failover_posture',
        max_requests: 3,
        secondary_nameservers: ['shop.example.test'],
      },
    }), {
      resolveNsFn: async () => ['ns1.example.test', 'ns2.example.test'],
      resolve4Fn: async () => { throw Object.assign(new Error('temporary'), { code: 'EAI_AGAIN' }); },
    });
    assert.equal(transient.external_result, 'error');
    assert.equal(transient.metadata.error_class, 'EAI_AGAIN');
    assert.equal(transient.requests_sent, 2);
  });

  it('DNS operation-budget errors propagate instead of becoming posture', async () => {
    await assert.rejects(
      () => probeDnsFailoverPosture(job({
        probe_profile: { kind: 'dns_failover_posture', max_requests: 3 },
      }), {
        recordProbeLogicalAttempt: () => {
          throw Object.assign(new Error('budget'), { code: 'signed_operation_budget_exceeded' });
        },
        resolveNsFn: async () => ['ns1.example.test'],
      }),
      (error) => error?.code === 'signed_operation_budget_exceeded',
    );
  });

  it('AXFR returns error for a transient NS lookup without destination resolution or connect', async () => {
    let destinationLookups = 0;
    let connectCalls = 0;
    const outcome = await probeAxfrLeak(job({
      target: { kind: 'fqdn', value: 'example.test' },
      probe_profile: { kind: 'dns_axfr_leak', max_requests: 2 },
    }), {
      resolveNsFn: async () => {
        throw Object.assign(new Error('temporary resolver failure'), { code: 'EAI_AGAIN' });
      },
      resolve4Fn: async () => { destinationLookups += 1; return ['203.0.113.53']; },
      resolve6Fn: async () => { destinationLookups += 1; return []; },
      connectFn: () => { connectCalls += 1; throw new Error('must not connect'); },
    });

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'EAI_AGAIN');
    assert.equal(outcome.requests_sent, 1);
    assert.equal(destinationLookups, 0);
    assert.equal(connectCalls, 0);
  });

  it('AXFR returns error when discovered NS AAAA lookup is transient despite a public A answer', async () => {
    let connectCalls = 0;
    const outcome = await probeAxfrLeak(job({
      target: { kind: 'fqdn', value: 'example.test' },
      probe_profile: { kind: 'dns_axfr_leak', max_requests: 2 },
    }), {
      resolveNsFn: async () => ['ns.example.test'],
      resolve4Fn: async () => ['203.0.113.53'],
      resolve6Fn: async () => {
        throw Object.assign(new Error('temporary resolver failure'), { code: 'EAI_AGAIN' });
      },
      connectFn: () => { connectCalls += 1; throw new Error('must not connect'); },
    });

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'EAI_AGAIN');
    assert.equal(outcome.requests_sent, 1);
    assert.equal(connectCalls, 0);
  });

  it('probeAxfrLeak accumulates split TCP response chunks before parsing', async () => {
    const refusedDns = Buffer.alloc(12);
    refusedDns.writeUInt16BE(0x4242, 0);
    refusedDns.writeUInt16BE(0x8005, 2);
    const refusedFramed = frameDnsTcpMessage(refusedDns);
    const chunk1 = refusedFramed.subarray(0, 4);
    const chunk2 = refusedFramed.subarray(4);
    let receivedQuery = null;

    const server = net.createServer((socket) => {
      socket.on('data', (buf) => {
        receivedQuery = buf;
        socket.write(chunk1, () => socket.write(chunk2));
      });
      socket.on('error', () => {});
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const { port } = server.address();

    try {
      const outcome = await probeAxfrLeak(job({
        probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
        target: { kind: 'fqdn', value: 'example.test' },
      }), {
        signedJobVerified: true,
        axfrTransactionId: 0x4242,
        // Local harness nameserver: loopback is opt-in for the destination guard, so this
        // fixture states that intent explicitly rather than relying on a default.
        destinationPolicy: { allowLoopback: true },
        resolveNsFn: async () => ['127.0.0.1'],
        connectFn: (opts) => net.connect({ ...opts, port }),
      });

      assert.ok(receivedQuery);
      assert.equal(receivedQuery.readUInt16BE(0), receivedQuery.length - 2);
      assert.equal(outcome.external_result, 'blocked');
      assert.equal(outcome.metadata.axfr_refused, true);
      assert.equal(outcome.metadata.rcode, 5);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('axfr derives the canonical zone from exact target A even when a corrupt profile names victim B', async () => {
    const victim = 'victim.example';
    const touched = [];
    let written = null;
    const refusedDns = Buffer.alloc(12);
    refusedDns.writeUInt16BE(0x4242, 0);
    refusedDns.writeUInt16BE(0x8005, 2);
    const refusedFramed = frameDnsTcpMessage(refusedDns);

    const outcome = await probeAxfrLeak(job({
      target: { kind: 'fqdn', value: 'Verified.Example.' },
      probe_profile: { kind: 'dns_axfr_leak', zone: victim },
    }), {
      signedJobVerified: true,
      axfrTransactionId: 0x4242,
      resolveNsFn: async (zone) => {
        touched.push(['resolveNs', zone]);
        assert.equal(zone, 'verified.example');
        return ['ns1.verified.example'];
      },
      resolve4Fn: async (host) => {
        touched.push(['resolve4', host]);
        assert.equal(host, 'ns1.verified.example');
        return ['203.0.113.53'];
      },
      resolve6Fn: async (host) => {
        touched.push(['resolve6', host]);
        assert.equal(host, 'ns1.verified.example');
        return [];
      },
      connectFn: (options) => {
        touched.push(['connect', options.host]);
        assert.equal(options.host, '203.0.113.53');
        return {
          once(event, handler) {
            if (event === 'connect') setImmediate(handler);
          },
          on(event, handler) {
            if (event === 'data') setImmediate(() => handler(refusedFramed));
          },
          write(buffer) {
            written = buffer;
          },
          destroy() {},
        };
      },
    });

    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.zone, 'verified.example');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.equal(outcome.requests_sent, 2);
    assert.ok(written.includes(encodeDnsQName('verified.example')));
    assert.equal(written.includes(encodeDnsQName(victim)), false);
    assert.equal(JSON.stringify(touched).includes(victim), false);
  });

  it('AXFR max_requests=1 fails before its NS lookup or TCP query', async () => {
    let resolverCalls = 0;
    let connectCalls = 0;
    const outcome = await probeAxfrLeak(job({
      constraints: { max_requests: 1, timeout_ms: 1000 },
      probe_profile: { kind: 'dns_axfr_leak', max_requests: 1 },
      target: { kind: 'fqdn', value: 'example.test' },
    }), {
      resolveNsFn: async () => { resolverCalls += 1; return ['ns1.example.test']; },
      connectFn: () => { connectCalls += 1; throw new Error('must not connect'); },
    });

    assert.equal(outcome.metadata.error_class, 'signed_request_budget_below_mandatory_floor');
    assert.equal(outcome.metadata.required_requests, 2);
    assert.equal(outcome.requests_sent, 0);
    assert.equal(resolverCalls, 0);
    assert.equal(connectCalls, 0);
  });

  it('axfr leak probe counts resolve-only when no nameservers', async () => {
    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'missing.test' },
      target: { kind: 'fqdn', value: 'missing.test' },
    }), {
      resolveNsFn: async () => [],
    });
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.equal(outcome.metadata.reason, 'no_nameservers');
    assert.equal(outcome.requests_sent, 1);
  });

  it('axfr leak probe sends TCP-framed query and treats REFUSED rcode as blocked', async () => {
    let written = null;
    const refusedDns = Buffer.alloc(12);
    refusedDns.writeUInt16BE(0x4242, 0);
    refusedDns.writeUInt16BE(0x8005, 2);
    const refusedFramed = frameDnsTcpMessage(refusedDns);

    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
        target: { kind: 'fqdn', value: 'example.test' },
    }), {
      axfrTransactionId: 0x4242,
      resolveNsFn: async () => ['ns1.example.test'],
      resolve4Fn: async () => ['203.0.113.53'],
      resolve6Fn: async () => [],
      connectFn: () => ({
        once(event, handler) {
          if (event === 'connect') setImmediate(() => handler());
        },
        on(event, handler) {
          if (event === 'data') setImmediate(() => handler(refusedFramed));
        },
        write(buf) {
          written = buf;
        },
        destroy() {},
      }),
    });

    assert.ok(written);
    assert.equal(written.readUInt16BE(0), written.length - 2);
    const inner = written.subarray(2);
    assert.equal(inner.readUInt16BE(encodeDnsQName('example.test').length + 12), 252);
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.notEqual(outcome.metadata.axfr_leak, true);
    assert.equal(outcome.requests_sent, 2);
  });

  it('axfr leak probe refuses a nameserver that resolves into RFC1918 space', async () => {
    let connectCalls = 0;
    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
        target: { kind: 'fqdn', value: 'example.test' },
    }), {
      signedJobVerified: true,
      resolveNsFn: async () => ['ns-internal.example.test'],
      resolve4Fn: async () => ['10.0.0.53'],
      resolve6Fn: async () => [],
      connectFn: () => { connectCalls += 1; throw new Error('must not connect'); },
    });
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'EDESTINATION');
    assert.equal(outcome.metadata.blocked_address, '10.0.0.53');
    assert.equal(connectCalls, 0);
  });

  it('axfr leak probe refuses a metadata-address nameserver literal', async () => {
    let connectCalls = 0;
    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
        target: { kind: 'fqdn', value: 'example.test' },
    }), {
      signedJobVerified: true,
      resolveNsFn: async () => ['169.254.169.254'],
      connectFn: () => { connectCalls += 1; throw new Error('must not connect'); },
    });
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'EDESTINATION');
    assert.equal(connectCalls, 0);
  });

  it('open recursion ignores a profile resolver and blocks the exact private target', async () => {
    let resolverCalls = 0;
    const outcome = await probeOpenRecursion(job({
      target: { kind: 'ip', value: '10.0.0.53' },
      probe_profile: { kind: 'dns_open_recursion', resolver_host: '8.8.8.8' },
    }), {
      resolve4ExternalFn: async () => { resolverCalls += 1; return []; },
    });
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'resolver_not_routable');
    assert.equal(outcome.metadata.blocked_address, '10.0.0.53');
    assert.equal(outcome.requests_sent, 0);
    assert.equal(resolverCalls, 0);
  });

  it('open recursion refuses an exact target that is not an IP literal', async () => {
    let resolverCalls = 0;
    const outcome = await probeOpenRecursion(job({
      target: { kind: 'fqdn', value: 'resolver.example.test' },
      probe_profile: { kind: 'dns_open_recursion', resolver_host: '8.8.8.8' },
    }), {
      resolve4ExternalFn: async () => { resolverCalls += 1; return []; },
    });
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'resolver_not_routable');
    assert.equal(outcome.metadata.reason, 'not_an_ip_literal');
    assert.equal(resolverCalls, 0);
  });

  it('tls audit refuses a host resolving to a non-routable address', async () => {
    let connectCalls = 0;
    const outcome = await probeTlsAudit(job({
      target: { kind: 'fqdn', value: 'internal.example.test' },
      probe_profile: { kind: 'tls_audit' },
    }), {
      resolve4Fn: async () => ['192.168.1.10'],
      resolve6Fn: async () => [],
      connectFn: () => { connectCalls += 1; throw new Error('must not connect'); },
    });
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'resolver_not_routable');
    assert.equal(outcome.metadata.blocked_address, '192.168.1.10');
    assert.equal(outcome.requests_sent, 0);
    assert.equal(connectCalls, 0);
  });

  it('port scan ignores a profile-supplied scan_host and uses the declared target', async () => {
    const probed = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 100, max_requests: 1 },
        target: { kind: 'ip', value: '198.51.100.9' },
        probe_profile: { kind: 'port_scan_bounded', ports: [443], scan_host: '169.254.169.254' },
      }),
      {
        connectFn: ({ host, port }) => {
          probed.push({ host, port });
          return {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
        },
      },
    );
    assert.deepEqual(probed, [{ host: '198.51.100.9', port: 443 }]);
    assert.equal(outcome.metadata.scan_host, '198.51.100.9');
  });

  it('parseDnsResponseHeader terminates a zero-length TCP frame in a single parse', () => {
    const parsed = parseDnsResponseHeader(Buffer.from([0x00, 0x00]), { transport: 'tcp' });
    assert.equal(parsed.incomplete, false);
    assert.equal(parsed.axfr_refused, true);
    assert.equal(parsed.reason, 'malformed_response');

    const accumulated = accumulateDnsTcpResponse(
      Buffer.alloc(0),
      Buffer.from([0x00, 0x00]),
      { transport: 'tcp' },
    );
    assert.equal(accumulated.complete, true);
    assert.equal(accumulated.parsed.axfr_refused, true);
  });

  it('accumulateDnsTcpResponse stops at the hard response ceiling', () => {
    const oversized = Buffer.alloc(MAX_DNS_TCP_RESPONSE_BYTES + 1);
    oversized.writeUInt16BE(0xffff, 0);
    const accumulated = accumulateDnsTcpResponse(Buffer.alloc(0), oversized, { transport: 'tcp' });
    assert.equal(accumulated.complete, true);
    assert.equal(accumulated.parsed.reason, 'response_too_large');
    assert.ok(accumulated.buffer.length <= MAX_DNS_TCP_RESPONSE_BYTES);
  });

  it('axfr session reports malformed_response for a zero-length frame without hanging', async () => {
    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
        target: { kind: 'fqdn', value: 'example.test' },
    }), {
      signedJobVerified: true,
      resolveNsFn: async () => ['203.0.113.53'],
      connectFn: () => ({
        once(event, handler) {
          if (event === 'connect') setImmediate(() => handler());
        },
        on(event, handler) {
          if (event === 'data') setImmediate(() => handler(Buffer.from([0x00, 0x00])));
        },
        write() {},
        destroy() {},
      }),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.equal(outcome.metadata.reason, 'malformed_response');
  });

  it('tls audit reports weak protocol issues', async () => {
    const outcome = await probeTlsAudit(job({
      probe_profile: { kind: 'tls_audit' },
    }), {
      resolve4Fn: async () => ['203.0.113.10'],
      resolve6Fn: async () => [],
      connectFn: () => ({
        once(event, handler) {
          if (event === 'secureConnect') handler();
        },
        getProtocol: () => 'TLSv1.1',
        getCipher: () => ({ name: 'RC4-SHA' }),
        authorized: false,
        getPeerCertificate: () => ({ valid_to: 'Jan 1 2020', issuer: { O: 'Test CA' }, subject: { CN: 'shop.example.test' } }),
        end() {},
      }),
    });
    assert.ok(outcome.metadata.tls_issues.includes('weak_tls_protocol'));
    assert.equal(outcome.external_result, 'connected');
  });

  it('cache abuse probe detects cache key weakness including bust variant', async () => {
    const outcome = await probeCacheAbuse(job({
      target: { value: 'https://cdn.example.test/asset' },
      probe_profile: { kind: 'cache_abuse_probe' },
    }), {
      fetchFn: async () => ({
        status: 200,
        headers: {
          get: (name) => {
            if (name === 'cache-control') return 'public, max-age=3600';
            if (name === 'x-cache') return 'HIT';
            return null;
          },
        },
      }),
    });
    assert.equal(outcome.metadata.cache_key_weakness, true);
    assert.equal(outcome.metadata.observations[1].x_cache, 'HIT');
  });

  it('cache abuse probe counts attempted requests even when every fetch fails', async () => {
    let attempts = 0;
    const outcome = await probeCacheAbuse(job({
      constraints: { max_requests: 3, timeout_ms: 1000 },
      target: { value: 'https://cdn.example.test/asset' },
      probe_profile: { kind: 'cache_abuse_probe', max_requests: 3 },
    }), {
      fetchFn: async () => {
        attempts += 1;
        throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
      },
    });

    assert.equal(attempts, 1);
    assert.equal(outcome.requests_sent, 1);
    assert.deepEqual(outcome.metadata.observations, []);
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'ECONNREFUSED');
    assert.equal(outcome.metadata.comparison_complete, false);
  });

  it('open recursion uses only exact target for resolver and query despite corrupt profile fields', async () => {
    const calls = [];
    const outcome = await probeOpenRecursion(job({
      target: { kind: 'ip', value: '8.8.8.8' },
      probe_profile: {
        kind: 'dns_open_recursion',
        resolver_host: '9.9.9.9',
        recursion_test_name: 'victim.example',
      },
    }), {
      resolve4ExternalFn: async (resolver, name) => {
        calls.push({ resolver, name });
        return ['8.8.8.8'];
      },
    });
    assert.deepEqual(calls, [{ resolver: '8.8.8.8', name: '8.8.8.8' }]);
    assert.equal(outcome.metadata.resolver_host, '8.8.8.8');
    assert.equal(outcome.metadata.recursion_test_name, '8.8.8.8');
    assert.equal(outcome.metadata.open_recursion_detected, true);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(JSON.stringify(calls).includes('victim.example'), false);
    assert.equal(JSON.stringify(calls).includes('9.9.9.9'), false);
  });

  it('open recursion errors without an exact target-derived resolver', async () => {
    let called = false;
    const outcome = await probeOpenRecursion(job({
      target: { kind: 'fqdn', value: '' },
      probe_profile: { kind: 'dns_open_recursion', resolver_host: '8.8.8.8' },
    }), {
      resolve4ExternalFn: async () => {
        called = true;
        return [];
      },
    });
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'unsupported_target');
    assert.equal(outcome.requests_sent, 0);
    assert.equal(called, false);
  });

  it('dns failover resolves only an exact-target secondary from a corrupt profile', async () => {
    const resolved = [];
    const outcome = await probeDnsFailoverPosture(job({
      target: { kind: 'fqdn', value: 'Shop.Example.Test.' },
      probe_profile: {
        kind: 'dns_failover_posture',
        secondary_nameservers: ['victim.example', 'shop.example.test'],
      },
    }), {
      resolveNsFn: async (zone) => {
        assert.equal(zone, 'Shop.Example.Test.');
        return ['ns1.example.test'];
      },
      resolve4Fn: async (host) => {
        resolved.push(host);
        return [];
      },
    });
    assert.deepEqual(resolved, ['shop.example.test']);
    assert.equal(JSON.stringify(resolved).includes('victim.example'), false);
    assert.deepEqual(outcome.metadata.secondary_results, [{
      nameserver: 'shop.example.test',
      reachable: false,
      addresses: [],
    }]);
    assert.equal(outcome.metadata.weak_failover, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('api surface scan finds exposed swagger path', async () => {
    const outcome = await probeApiSurfaceScan(job({
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'api_surface_scan', paths: ['/swagger.json', '/missing'] },
    }), {
      fetchFn: async (url) => ({
        status: String(url).endsWith('/swagger.json') ? 200 : 404,
        headers: { get: () => null },
      }),
    });
    assert.equal(outcome.metadata.exposure_count, 1);
    assert.equal(outcome.external_result, 'connected');
  });

  it('api surface scan does not report protected when every path has a transport error', async () => {
    const outcome = await probeApiSurfaceScan(job({
      constraints: { max_requests: 2, timeout_ms: 1000 },
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'api_surface_scan', paths: ['/swagger.json', '/openapi.json'] },
    }), {
      fetchFn: async () => {
        throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
      },
    });

    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.exposure_count, 0);
    assert.equal(outcome.metadata.path_errors.length, 2);
    assert.equal(outcome.metadata.error_class, 'ECONNREFUSED');
  });

  it('cors posture flags wildcard ACAO', async () => {
    const outcome = await probeCorsPosture(job({
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'cors_posture_probe' },
    }), {
      fetchFn: async () => ({
        status: 204,
        headers: { get: (n) => (n === 'access-control-allow-origin' ? '*' : null) },
      }),
    });
    assert.equal(outcome.metadata.weak_cors, true);
  });

  it('semantic HTTP checks classify connection failures as errors, not protection', async () => {
    const refused = async () => {
      throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
    };
    const scenarios = [
      probeWafEnforcement(job({
        target: { value: 'https://app.example.test' },
        probe_profile: { kind: 'waf_enforcement_probe' },
      }), { fetchFn: refused }),
      probeCorsPosture(job({
        target: { value: 'https://app.example.test' },
        probe_profile: { kind: 'cors_posture_probe' },
      }), { fetchFn: refused }),
      probeBotChallenge(job({
        target: { value: 'https://app.example.test' },
        probe_profile: { kind: 'bot_challenge_probe' },
      }), { fetchFn: refused }),
      probeGraphqlPosture(job({
        target: { value: 'https://app.example.test' },
        probe_profile: { kind: 'graphql_posture_probe' },
      }), { fetchFn: refused }),
    ];

    for (const outcome of await Promise.all(scenarios)) {
      assert.equal(outcome.external_result, 'error', outcome.metadata.probe_kind);
      assert.equal(outcome.metadata.error_class, 'ECONNREFUSED');
    }
  });

  it('bot challenge probe flags missing challenge', async () => {
    const outcome = await probeBotChallenge(job({
      target: { value: 'https://app.example.test' },
      probe_profile: { kind: 'bot_challenge_probe' },
    }), {
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.metadata.bot_challenge_missing, true);
  });

  it('graphql posture flags exposed endpoint without limits', async () => {
    const outcome = await probeGraphqlPosture(job({
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'graphql_posture_probe', graphql_path: '/graphql' },
    }), {
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.metadata.graphql_exposed, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('executeCapabilityProbe dispatches by profile kind', async () => {
    const outcome = await executeCapabilityProbe(job({
      probe_profile: { kind: 'bot_challenge_probe' },
      target: { value: 'https://app.example.test' },
    }), {
      fetchFn: async () => ({ status: 403, headers: { get: () => 'challenge' } }),
    });
    assert.equal(outcome.metadata.probe_kind, 'bot_challenge_probe');
    assert.equal(outcome.external_result, 'blocked');
  });

  it('executeCapabilityProbe blocks unsigned live probes without injectable deps', async () => {
    const outcome = await executeCapabilityProbe(job({
      probe_profile: {
        kind: 'host_sni_bypass',
        protected_host: 'edge.example.test',
        direct_ip: '198.51.100.7',
      },
    }));
    assert.equal(outcome.metadata.probe_kind, 'host_sni_bypass');
    assert.equal(outcome.metadata.error_class, 'live_probe_requires_signed_worker');
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.requests_sent, 0);
  });

  it('isLiveCapabilityProbeAuthorized accepts signed worker verification context', () => {
    assert.equal(isLiveCapabilityProbeAuthorized(job(), { signedJobVerified: true }), true);
    assert.equal(isLiveCapabilityProbeAuthorized(job(), {}), false);
    assert.equal(
      isLiveCapabilityProbeAuthorized(job(), { fetchFn: async () => ({ status: 200, headers: { get: () => null } }) }),
      true,
    );
  });

  it('catalog includes full P0/P1 capability checks with live probe kinds', () => {
    const ids = [
      'origin.leak_scan.safe',
      'l3.firewall_exposure_scan.safe',
      'waf.enforcement.safe',
      'tls.full_audit.safe',
      'l7.api_surface_scan.safe',
      'l7.cors_posture.safe',
    ];
    for (const id of ids) {
      const check = getCheckById(id);
      assert.ok(check, `missing ${id}`);
      assert.notEqual(check.probe_profile.kind, 'metadata_marker', `${id} still metadata_marker`);
    }
    assert.equal(getCheckById('origin.host_sni_bypass.safe').probe_profile.kind, 'host_sni_bypass');
    assert.equal(getCheckById('l7.login_abuse_flow.safe').probe_profile.kind, 'rate_limit_sequence');
    assert.equal(getCheckById('dns.zone_transfer_exposure.safe').probe_profile.kind, 'dns_axfr_leak');
    assert.equal(getCheckById('dns.secondary_failover.safe').probe_profile.kind, 'dns_failover_posture');
    assert.equal(getCheckById('l7.bot_challenge_marker.safe').probe_profile.kind, 'bot_challenge_probe');
    assert.equal(getCheckById('origin.direct_bypass.safe').probe_profile.kind, 'host_sni_bypass');
    assert.equal(getCheckById('waf.marker_rule.safe').probe_profile.kind, 'waf_enforcement_probe');
    assert.equal(getCheckById('waf.origin_bypass.safe').probe_profile.kind, 'host_sni_bypass');
    assert.equal(getCheckById('tls.profile_exposure.safe').probe_profile.kind, 'tls_audit');
    assert.equal(getCheckById('l7.api_quota_exhaustion.safe').probe_profile.kind, 'rate_limit_sequence');
    assert.equal(getCheckById('protocol.http2_readiness.safe').probe_profile.kind, 'http2_settings');
  });
});


describe('origin edge transport failure safety', () => {
  it('returns a bounded error without subdomain scans or leak inference on ECONNRESET', async () => {
    const resolutions = [];
    let headCalls = 0;
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 15, max_probe_requests: 15, timeout_ms: 1000 },
      probe_profile: { kind: 'origin_leak_scan', max_requests: 15, timeout_ms: 1000 },
    }), {
      resolve4Fn: async (host) => {
        resolutions.push(['A', host]);
        return host === 'shop.example.test' ? ['203.0.113.10'] : [];
      },
      resolve6Fn: async (host) => {
        resolutions.push(['AAAA', host]);
        return [];
      },
      fetchFn: async () => {
        headCalls += 1;
        throw Object.assign(new Error('connection reset'), { code: 'ECONNRESET' });
      },
    });

    assert.deepEqual(resolutions, [
      ['A', 'shop.example.test'],
      ['AAAA', 'shop.example.test'],
    ]);
    assert.equal(headCalls, 1);
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'ECONNRESET');
    assert.equal(outcome.requests_sent, 3);
    assert.equal(outcome.metadata.resolver_attempts, 2);
    assert.equal(outcome.metadata.http_attempts, 1);
    assert.deepEqual(outcome.metadata.subdomains_scanned, []);
    assert.deepEqual(outcome.metadata.leak_signals, []);
    assert.equal(outcome.metadata.leak_count, 0);
    assert.equal(outcome.metadata.leak_signals.includes('dns_only_no_edge_http'), false);
  });
});
