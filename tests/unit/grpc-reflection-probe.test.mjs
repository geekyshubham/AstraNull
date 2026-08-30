import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { probeGrpcReflection } from '../../src/lib/capabilityProbes.mjs';
import { buildProbeProfile, getCheckById } from '../../src/contracts/checks.mjs';
import { runProtocolTransportFixture } from './protocol-transport-watchdog.mjs';

function makeJob(overrides = {}) {
  return {
    job_id: 'pj_test_grpc',
    tenant_id: 'ten_demo',
    target: { id: 'tgt_1', kind: 'url', value: 'https://grpc.test:8443' },
    probe_profile: buildProbeProfile({ kind: 'grpc_reflection_probe', max_requests: 1, timeout_ms: 5000 }),
    constraints: { timeout_ms: 5000, max_requests: 1 },
    ...overrides,
  };
}

function h2Response({
  grpcStatus = '0',
  initialGrpcStatus = null,
  grpcMessage = null,
  contentType = 'application/grpc',
} = {}) {
  const headers = new Map([['content-type', contentType]]);
  if (initialGrpcStatus !== null) headers.set('grpc-status', initialGrpcStatus);
  const trailers = new Map();
  if (grpcStatus !== null) trailers.set('grpc-status', grpcStatus);
  if (grpcMessage !== null) trailers.set('grpc-message', grpcMessage);
  return {
    status: 200,
    httpVersion: '2.0',
    pinnedAddress: '93.184.216.34',
    headers,
    trailers,
  };
}

describe('grpc_reflection_probe (DET-021)', () => {
  it('catalog check uses the bounded gRPC probe kind', () => {
    const check = getCheckById('protocol.grpc_reflection_stream.safe');
    assert.ok(check);
    assert.equal(check.probe_profile.kind, 'grpc_reflection_probe');
    assert.equal(check.probe_profile.max_requests, 1);
  });

  it('sends one valid reflection frame and prefers trailer grpc-status', async () => {
    let captured = null;
    const result = await probeGrpcReflection(makeJob(), {
      http2RequestFn: async (url, options) => {
        captured = { url, options };
        return h2Response({
          initialGrpcStatus: '12',
          grpcStatus: '0',
          grpcMessage: 'ok',
        });
      },
    });

    assert.equal(
      captured.url,
      'https://grpc.test:8443/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
    );
    assert.equal(captured.options.method, 'POST');
    assert.equal(captured.options.headers.TE, 'trailers');
    assert.deepEqual(captured.options.body, Buffer.from([0, 0, 0, 0, 2, 0x3a, 0]));
    assert.equal(result.external_result, 'connected');
    assert.equal(result.requests_sent, 1);
    assert.equal(result.metadata.grpc_status, '0');
    assert.equal(result.metadata.grpc_status_source, 'trailers');
    assert.equal(result.metadata.grpc_endpoint_reachable, true);
    assert.equal(result.metadata.grpc_probe_service, 'reflection');
    assert.equal(result.metadata.grpc_transport, 'h2_tls');
    assert.equal(result.metadata.pinned_address, '93.184.216.34');
    assert.equal(result.metadata.reflection_service_routed, true);
    assert.equal(result.metadata.reflection_service_exposed, true);
    assert.equal(result.metadata.response_body_retained, false);
  });

  it('refuses to infer gRPC metadata from an HTTP/1-style response', async () => {
    const result = await probeGrpcReflection(makeJob(), {
      http2RequestFn: async () => ({
        status: 200,
        headers: new Map([['grpc-status', '0'], ['content-type', 'application/grpc']]),
      }),
    });
    assert.equal(result.external_result, 'error');
    assert.equal(result.metadata.error_class, 'grpc_http2_required');
    assert.equal(result.metadata.reflection_service_routed, null);
  });

  it('classifies unreachable HTTP/2 endpoints as blocked', async () => {
    const result = await probeGrpcReflection(makeJob(), {
      http2RequestFn: async () => {
        throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
      },
    });
    assert.equal(result.external_result, 'blocked');
    assert.equal(result.metadata.error_class, 'ECONNREFUSED');
    assert.equal(result.metadata.reflection_service_routed, null);
  });

  it('treats trailer UNIMPLEMENTED on the reflection method as not routed', async () => {
    const result = await probeGrpcReflection(makeJob(), {
      http2RequestFn: async () => h2Response({ grpcStatus: '12' }),
    });
    assert.equal(result.external_result, 'blocked');
    assert.equal(result.metadata.grpc_endpoint_reachable, true);
    assert.equal(result.metadata.reflection_service_routed, false);
    assert.equal(result.metadata.reflection_service_exposed, false);
  });

  it('uses a valid empty health request without claiming reflection', async () => {
    let body = null;
    const base = makeJob();
    const result = await probeGrpcReflection(makeJob({
      probe_profile: { ...base.probe_profile, grpc_path: '/grpc.health.v1.Health/Check' },
    }), {
      http2RequestFn: async (_url, options) => {
        body = options.body;
        return h2Response();
      },
    });
    assert.deepEqual(body, Buffer.from([0, 0, 0, 0, 0]));
    assert.equal(result.external_result, 'connected');
    assert.equal(result.metadata.grpc_probe_service, 'health');
    assert.equal(result.metadata.reflection_service_routed, null);
    assert.equal(result.metadata.reflection_service_exposed, false);
  });

  it('fails unknown protobuf methods honestly without sending a request', async () => {
    let requests = 0;
    const base = makeJob();
    const result = await probeGrpcReflection(makeJob({
      probe_profile: { ...base.probe_profile, grpc_path: '/custom.Service/Unknown' },
    }), {
      http2RequestFn: async () => { requests += 1; },
    });
    assert.equal(result.external_result, 'error');
    assert.equal(result.metadata.error_class, 'unsupported_grpc_method');
    assert.equal(result.metadata.reflection_service_routed, null);
    assert.equal(result.requests_sent, 0);
    assert.equal(requests, 0);
  });

  it('requires TLS HTTP/2 instead of falling back to cleartext HTTP/1.1', async () => {
    const result = await probeGrpcReflection(makeJob({
      target: { id: 'tgt_1', kind: 'url', value: 'http://grpc.test:8080' },
    }), {});
    assert.equal(result.external_result, 'error');
    assert.equal(result.metadata.error_class, 'grpc_http2_tls_required');
    assert.equal(result.requests_sent, 0);
  });

  it('rejects targets without a resolvable host', async () => {
    const result = await probeGrpcReflection(makeJob({ target: { id: 'tgt_1', kind: 'url', value: '' } }), {});
    assert.equal(result.external_result, 'error');
    assert.equal(result.metadata.error_class, 'unsupported_target');
  });

  it('pins a real TLS HTTP/2 socket, preserves SNI/authority, and reads trailers', { timeout: 6000 }, async () => {
    const output = await runProtocolTransportFixture('grpc');
    assert.match(output.stdout, /grpc:ok/);
  });
});
