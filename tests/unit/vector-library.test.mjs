import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { mintSignedSessionToken } from '../../src/context.mjs';
import {
  VECTOR_LIBRARY,
  VECTOR_LIBRARY_TOTAL,
} from '../../src/contracts/vectorLibrary.mjs';
import { buildVectorTargetMatrix } from '../../src/contracts/vectorTargetMatrix.mjs';
import {
  VECTOR_CATALOG,
  VECTOR_CATALOG_TOTAL,
} from '../../src/lib/data/vectorCatalog.generated.mjs';
import { listVectors } from '../../src/services/vectorLibrary.mjs';
import { closeServer, request, signedSessionHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const PUBLIC_FIELDS = [
  'vector_id',
  'section',
  'domain',
  'scope',
  'family',
  'canonical_name',
  'protocol_service',
  'delivery_mechanism',
  'how_it_works',
  'targeted_resource_or_assumption',
  'defensive_indicators',
  'primary_controls',
  'boundaries',
  'validation_tier',
];

describe('721-vector library contract', () => {
  it('keeps the generated public projection complete, unique, and field-limited', () => {
    assert.equal(VECTOR_CATALOG_TOTAL, 721);
    assert.equal(VECTOR_CATALOG.length, 721);
    assert.equal(new Set(VECTOR_CATALOG.map((row) => row.vector_id)).size, 721);
    for (const row of VECTOR_CATALOG) {
      assert.deepEqual(Object.keys(row), PUBLIC_FIELDS);
      assert.match(row.vector_id, /^(NET|AMP|APP|WAF|EVA)-\d{3}$/);
      assert.ok(row.canonical_name);
    }
  });

  it('joins every ID once and preserves the 680 in-scope plus 41 out-of-scope partition', () => {
    assert.equal(VECTOR_LIBRARY_TOTAL, 721);
    assert.equal(VECTOR_LIBRARY.length, 721);
    assert.equal(new Set(VECTOR_LIBRARY.map((row) => row.vector_id)).size, 721);
    const outside = VECTOR_LIBRARY.filter((row) => row.registry_source === 'OUT_OF_SCOPE_VECTORS');
    assert.equal(outside.length, 41);
    assert.equal(VECTOR_LIBRARY.length - outside.length, 680);
    assert.ok(outside.every((row) => (
      row.execution_disposition === 'monitor_only'
        && row.evidence_capability === 'monitor_only'
        && row.evidence_tier === 'E5'
    )));
    for (const row of VECTOR_LIBRARY) {
      assert.equal(new Set(row.check_ids).size, row.check_ids.length, row.vector_id);
      assert.equal(row.check_ids.length, row.safe_check_ids.length + row.soc_check_ids.length);
      assert.equal('detects' in row, false, row.vector_id);
      assert.match(row.intended_detection_goal, /^Intent only:/, row.vector_id);
      assert.match(row.intended_detection_goal, /not an observed or detected result/i, row.vector_id);
      assert.ok(row.failure_means, row.vector_id);
      assert.equal(typeof row.expected_controls, 'string');
      assert.equal(row.expected_controls, row.primary_controls);
      assert.equal(row.metadata_available, row.metadata_check_ids.length > 0, row.vector_id);
    }
  });

  it('keeps APP-003 and NET-016 SOC-governed while preserving declaration metadata', () => {
    for (const [vectorId, metadataCheckId] of [
      ['APP-003', 'l7.http_post_flood.validation'],
      ['NET-016', 'l3.icmp_flood.readiness'],
    ]) {
      const row = VECTOR_LIBRARY.find((candidate) => candidate.vector_id === vectorId);
      assert.ok(row, vectorId);
      assert.equal(row.evidence_tier, 'E4', vectorId);
      assert.equal(row.evidence_capability, 'soc_governed', vectorId);
      assert.equal(row.execution_disposition, 'soc_gated_only', vectorId);
      assert.equal(row.metadata_available, true, vectorId);
      assert.ok(row.metadata_check_ids.includes(metadataCheckId), vectorId);
      assert.deepEqual(row.semantic_safe_check_ids, [], vectorId);
      assert.match(row.intended_detection_goal, /^Intent only:/, vectorId);
      assert.match(row.failure_means, /supplemental declaration or transport evidence is not an exposure result/i, vectorId);
      assert.equal('detects' in row, false, vectorId);
    }
  });

  it('classifies APP-001 as a genuine semantic-safe rate-limit row', () => {
    const rateLimit = VECTOR_LIBRARY.find((row) => row.vector_id === 'APP-001');
    assert.ok(rateLimit);
    assert.equal(rateLimit.evidence_tier, 'E3');
    assert.equal(rateLimit.evidence_capability, 'semantic_safe');
    assert.equal(rateLimit.execution_disposition, 'safe_validation_available');
    assert.ok(rateLimit.semantic_safe_check_ids.includes('l7.http_get_flood.validation'));
    assert.match(rateLimit.failure_means, /throttle|challenge/i);
    assert.match(rateLimit.failure_means, /declared RPS limits/i);
    assert.equal(rateLimit.expected_controls, rateLimit.primary_controls);
  });

  it('provides bounded deterministic pagination, search, and filters', () => {
    const page = listVectors({ offset: 3, limit: 7 });
    assert.equal(page.items.length, 7);
    assert.deepEqual(page.items, VECTOR_LIBRARY.slice(3, 10));
    assert.deepEqual(page.meta, {
      total: 721,
      filtered_total: 721,
      offset: 3,
      limit: 7,
      returned: 7,
    });

    const bounded = listVectors({ limit: 9999, offset: -20 });
    assert.equal(bounded.items.length, 100);
    assert.equal(bounded.meta.limit, 100);
    assert.equal(bounded.meta.offset, 0);

    const sample = VECTOR_LIBRARY[0];
    const searched = listVectors({ q: sample.vector_id.toLowerCase(), limit: 10 });
    assert.deepEqual(searched.items.map((row) => row.vector_id), [sample.vector_id]);
    const descriptiveSearch = listVectors({ q: 'ANY-like', limit: 10 });
    assert.deepEqual(descriptiveSearch.items.map((row) => row.vector_id), ['AMP-001']);
    const filtered = listVectors({
      section: sample.section.toUpperCase(),
      evidence_tier: sample.evidence_tier,
      evidence_capability: sample.evidence_capability,
      execution_disposition: sample.execution_disposition,
      limit: 100,
    });
    assert.ok(filtered.items.length > 0);
    assert.ok(filtered.items.every((row) => (
      row.section === sample.section
        && row.evidence_tier === sample.evidence_tier
        && row.evidence_capability === sample.evidence_capability
        && row.execution_disposition === sample.execution_disposition
    )));
    assert.equal(filtered.meta.total, 721);
  });

  it('accounts for every row in the FQDN external-only no-agent matrix', () => {
    const matrix = buildVectorTargetMatrix();
    assert.deepEqual(matrix.profile, {
      target_kind: 'fqdn',
      validation_mode: 'external_only',
      agent: 'none',
    });
    assert.equal(matrix.rows.length, 721);
    assert.equal(new Set(matrix.rows.map((row) => row.vector_id)).size, 721);
    assert.equal(
      Object.values(matrix.summary.dispositions).reduce((total, count) => total + count, 0),
      721,
    );
    assert.equal(
      new Set(matrix.runnable_safe_check_ids).size,
      matrix.runnable_safe_check_ids.length,
    );
    const rowRunnableIds = new Set(matrix.rows.flatMap((row) => row.runnable_safe_check_ids));
    assert.deepEqual([...rowRunnableIds].sort(), matrix.runnable_safe_check_ids);
    assert.equal(matrix.summary.runnable_safe_check_count, matrix.runnable_safe_check_ids.length);
    assert.deepEqual(matrix.summary.evidence_capabilities, {
      semantic_safe: 271,
      soc_governed: 258,
      declaration_only: 104,
      transport_only: 39,
      monitor_only: 49,
    });
    assert.deepEqual(matrix.summary.execution_dispositions, {
      safe_validation_available: 414,
      soc_gated_only: 258,
      monitor_only: 49,
    });
    assert.deepEqual(matrix.summary.evidence_execution_matrix, {
      semantic_safe: { safe_validation_available: 271 },
      soc_governed: { soc_gated_only: 258 },
      declaration_only: { safe_validation_available: 104 },
      transport_only: { safe_validation_available: 39 },
      monitor_only: { monitor_only: 49 },
    });
    for (const vectorId of ['APP-003', 'NET-016']) {
      const row = matrix.rows.find((candidate) => candidate.vector_id === vectorId);
      assert.equal(row?.target_disposition, 'soc_gated', vectorId);
      assert.deepEqual(row?.runnable_safe_check_ids, [], vectorId);
      assert.equal(row?.metadata_available, true, vectorId);
      assert.ok((row?.supplemental_safe_check_ids.length ?? 0) > 0, vectorId);
    }
    for (const row of matrix.rows) {
      assert.equal(new Set(row.runnable_safe_check_ids).size, row.runnable_safe_check_ids.length);
      assert.ok(row.runnable_safe_check_ids.every((checkId) => row.safe_check_ids.includes(checkId)));
    }
  });
});

describe('GET /v1/vectors', () => {
  let server;
  let baseUrl;
  let startTestRunCalls;

  before(async () => {
    freshStore();
    startTestRunCalls = 0;
    server = createServer({
      env: {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_AUTH_MODE: 'signed-session',
        ASTRANULL_SESSION_SECRET: 'vector-library-test-session-secret-2026',
        ASTRANULL_NO_PERSIST: '1',
      },
      services: {
        testRuns: {
          startTestRun() {
            startTestRunCalls += 1;
            throw new Error('vector route must not start a test run');
          },
        },
      },
    });
    await new Promise((resolve) => server.listen(0, resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => closeServer(server));

  it('requires authentication and exposes bounded pagination/filter metadata', async () => {
    const denied = await request(baseUrl, 'GET', '/v1/vectors?limit=2');
    assert.equal(denied.status, 401);

    const sample = VECTOR_LIBRARY[0];
    const response = await request(
      baseUrl,
      'GET',
      `/v1/vectors?limit=2&offset=1&section=${encodeURIComponent(sample.section)}`,
      { headers: signedSessionHeaders(
        'viewer',
        'ten_demo',
        'usr_viewer',
        'vector-library-test-session-secret-2026',
        mintSignedSessionToken,
      ) },
    );
    assert.equal(response.status, 200);
    assert.equal(response.json.items.length, 2);
    assert.equal(response.json.meta.total, 721);
    assert.equal(response.json.meta.limit, 2);
    assert.equal(response.json.meta.offset, 1);
    assert.ok(response.json.items.every((row) => row.section === sample.section));
    assert.ok(response.json.items.every((row) => !('detects' in row)));
    assert.ok(response.json.items.every((row) => row.intended_detection_goal.startsWith('Intent only:')));

    const searched = await request(
      baseUrl,
      'GET',
      `/v1/vectors?q=${encodeURIComponent(sample.vector_id)}&limit=9999`,
      { headers: signedSessionHeaders(
        'viewer',
        'ten_demo',
        'usr_viewer',
        'vector-library-test-session-secret-2026',
        mintSignedSessionToken,
      ) },
    );
    assert.equal(searched.status, 200);
    assert.equal(searched.json.meta.total, 721);
    assert.equal(searched.json.meta.limit, 100);
    assert.deepEqual(searched.json.items.map((row) => row.vector_id), [sample.vector_id]);
    assert.equal(startTestRunCalls, 0);
  });

  it('uses the same metadata-only service in Postgres mode', async () => {
    const sessionSecret = 'vector-library-postgres-test-session-secret-2026';
    const postgresServer = createServer({
      env: {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_AUTH_MODE: 'signed-session',
        ASTRANULL_SESSION_SECRET: sessionSecret,
        ASTRANULL_PERSISTENCE_MODE: 'postgres',
        ASTRANULL_DATABASE_URL: 'postgres://unused:unused@127.0.0.1:1/unused',
      },
    });
    await new Promise((resolve) => postgresServer.listen(0, resolve));
    const postgresBaseUrl = `http://127.0.0.1:${postgresServer.address().port}`;
    try {
      const response = await request(postgresBaseUrl, 'GET', '/v1/vectors?limit=1', {
        headers: signedSessionHeaders(
          'viewer',
          'ten_demo',
          'usr_viewer',
          sessionSecret,
          mintSignedSessionToken,
        ),
      });
      assert.equal(response.status, 200);
      assert.equal(response.json.meta.total, 721);
      assert.equal(response.json.items.length, 1);
    } finally {
      await closeServer(postgresServer);
    }
  });
});
