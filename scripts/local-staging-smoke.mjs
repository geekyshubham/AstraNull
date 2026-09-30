#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
  DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
  DEFAULT_LOCAL_STAGING_BASE_URL,
  DEFAULT_LOCAL_STAGING_TENANT_ID,
  LOCAL_STAGING_DEMO_IDS,
} from './lib/localStaging.mjs';
import { resolveStagingAuthHeaders } from './lib/stagingAuth.mjs';
import { resolveStagingProbeWorkerSecret } from './lib/hostedStaging.mjs';
import { parseWorkerConfig, pollAndProcessOnce } from '../workers/probe-worker.mjs';

/**
 * @param {string} baseUrl
 * @param {string} pathname
 * @param {{ method?: string, headers?: Record<string, string>, body?: unknown }} [options]
 */
/**
 * Check used for the bounded smoke run: customer-selectable (no extra run-time input) and
 * backed by the signed-worker origin leak scan path.
 */
const SMOKE_CHECK_ID = 'origin.leak_scan.safe';

export async function stagingFetch(baseUrl, pathname, options = {}) {
  const url = new URL(pathname, baseUrl);
  const headers = {
    accept: 'application/json',
    ...(options.headers ?? {}),
  };
  let body;
  if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(options.body);
  }
  const response = await fetch(url, {
    method: options.method ?? 'GET',
    headers,
    body,
  });
  const text = await response.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
  }
  return { status: response.status, json };
}

export function buildDevHeaders(
  tenantId = DEFAULT_LOCAL_STAGING_TENANT_ID,
  userId = DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
  role = DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
) {
  return {
    'x-tenant-id': tenantId,
    'x-user-id': userId,
    'x-role': role,
  };
}

function expectStatus(response, expected, label) {
  if (response.status !== expected) {
    const error = response.json?.error ? ` (${response.json.error})` : '';
    throw new Error(`${label} expected ${expected} (got ${response.status})${error}`);
  }
}

function expectArrayResponse(response, label, keys) {
  for (const key of keys) {
    if (Array.isArray(response.json?.[key])) return response.json[key];
  }
  throw new Error(`${label} expected ${keys.map((key) => `${key}[]`).join(' or ')} (got ${response.status})`);
}

function uniqueSmokeLabel(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

async function cancelActiveDemoRuns(baseUrl, headers) {
  let cancelledCount = 0;
  for (let round = 0; round < 6; round += 1) {
    const listed = await stagingFetch(baseUrl, '/v1/test-runs', { headers });
    expectStatus(listed, 200, 'GET /v1/test-runs');
    const runs = expectArrayResponse(listed, 'GET /v1/test-runs', ['items']);
    const activeRuns = runs.filter(
      (run) =>
        run.target_group_id === LOCAL_STAGING_DEMO_IDS.targetGroupId &&
        ['planned', 'running', 'collecting'].includes(run.status),
    );
    if (activeRuns.length === 0) break;
    for (const run of activeRuns) {
      const cancelled = await stagingFetch(baseUrl, `/v1/test-runs/${run.id}/cancel`, {
        method: 'POST',
        headers,
      });
      expectStatus(cancelled, 200, `POST /v1/test-runs/${run.id}/cancel`);
      cancelledCount += 1;
    }
    if (round < 5) {
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
  }
  return cancelledCount;
}

/**
 * @param {string} baseUrl
 * @param {Record<string, string>} headers
 */
export async function runLocalStagingValidationLoopSmoke(baseUrl, headers = buildDevHeaders()) {
  const checks = [];
  const cancelledRuns = await cancelActiveDemoRuns(baseUrl, headers);
  if (cancelledRuns > 0) checks.push('active_runs_cleared');

  const started = await stagingFetch(baseUrl, '/v1/test-runs', {
    method: 'POST',
    headers,
    body: {
      check_id: SMOKE_CHECK_ID,
      target_group_id: LOCAL_STAGING_DEMO_IDS.targetGroupId,
      target_id: LOCAL_STAGING_DEMO_IDS.targetId,
    },
  });
  expectStatus(started, 201, 'POST /v1/test-runs');
  const run = started.json?.run;
  const runId = run?.id;
  const nonceHash = run?.correlation?.nonce_hash;
  if (!runId || !nonceHash) {
    throw new Error('POST /v1/test-runs expected run.id and run.correlation.nonce_hash');
  }
  checks.push('safe_validation_started');

  const ready = await stagingFetch(baseUrl, '/ready');
  const probeMode = ready.json?.probe_mode ?? ready.json?.probeMode ?? 'simulation';
  if (probeMode === 'signed-worker') {
    const probeSecret = resolveStagingProbeWorkerSecret(baseUrl);
    const workerConfig = parseWorkerConfig([], {
      ASTRANULL_API_URL: baseUrl,
      ASTRANULL_PROBE_WORKER_SECRET: probeSecret,
      ASTRANULL_PROBE_TENANT_ID: DEFAULT_LOCAL_STAGING_TENANT_ID,
      ASTRANULL_PROBE_WORKER_ID: uniqueSmokeLabel('probe-worker'),
      ASTRANULL_PROBE_ONCE: '1',
    });
    if (!started.json?.probe_job?.id) {
      throw new Error('POST /v1/test-runs expected probe_job.id in signed-worker mode');
    }
    let probeResults = [];
    for (let attempt = 0; attempt < 10; attempt += 1) {
      probeResults = await pollAndProcessOnce(workerConfig);
      if (Array.isArray(probeResults) && probeResults.length >= 1) break;
      const events = await stagingFetch(baseUrl, `/v1/test-runs/${runId}/events`, { headers });
      if (events.status === 200) {
        const eventItems = events.json?.items ?? events.json?.events ?? [];
        if (eventItems.some((event) => event.signal_type === 'probe_result')) {
          probeResults = [{ job_id: started.json.probe_job.id, external_result: 'hosted_probe_worker' }];
          break;
        }
      }
      if (attempt < 9) {
        await new Promise((resolve) => setTimeout(resolve, 800));
      }
    }
    if (!Array.isArray(probeResults) || probeResults.length < 1) {
      throw new Error(
        `signed-worker smoke expected at least one processed probe job (probe_job=${started.json.probe_job.id})`,
      );
    }
    checks.push('signed_probe_worker_processed');
  }

  let detail = null;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    detail = await stagingFetch(baseUrl, `/v1/test-runs/${runId}`, { headers });
    expectStatus(detail, 200, `GET /v1/test-runs/${runId}`);
    if (detail.json?.status === 'verdicted' && detail.json?.verdict?.verdict) break;
    if (attempt < 9) {
      await new Promise((resolve) => setTimeout(resolve, 800));
    }
  }
  if (detail?.json?.status !== 'verdicted' || !detail.json?.verdict?.verdict) {
    throw new Error(`GET /v1/test-runs/${runId} expected verdicted run`);
  }
  checks.push('verdict_readback');

  const events = await stagingFetch(baseUrl, `/v1/test-runs/${runId}/events`, { headers });
  expectStatus(events, 200, `GET /v1/test-runs/${runId}/events`);
  const eventItems = expectArrayResponse(events, `GET /v1/test-runs/${runId}/events`, ['items']);
  if (!eventItems.some((event) => event.signal_type === 'probe_result')) {
    throw new Error(`GET /v1/test-runs/${runId}/events expected probe_result event`);
  }
  checks.push('evidence_events_readback');

  const findings = await stagingFetch(baseUrl, '/v1/findings', { headers });
  expectStatus(findings, 200, 'GET /v1/findings');
  const findingItems = expectArrayResponse(findings, 'GET /v1/findings', ['items']);
  const runFinding = findingItems.find((entry) => entry.test_run_id === runId);
  const verdictLabel = detail.json?.verdict?.verdict;
  if (runFinding) {
    checks.push('findings_readback');
  } else if (['pass', 'protected', 'inconclusive'].includes(verdictLabel)) {
    checks.push('findings_optional_for_pass_verdict');
  } else {
    throw new Error(
      `GET /v1/findings expected finding for ${runId} or pass/protected verdict (got verdict=${verdictLabel ?? 'unknown'})`,
    );
  }

  const report = await stagingFetch(baseUrl, '/v1/reports', {
    method: 'POST',
    headers,
    body: { kind: 'technical' },
  });
  expectStatus(report, 201, 'POST /v1/reports');
  const reportId = report.json?.id;
  if (!reportId || typeof report.json?.summary?.readiness_score !== 'number') {
    throw new Error('POST /v1/reports expected id and numeric readiness_score');
  }
  checks.push('report_created');

  const exported = await stagingFetch(baseUrl, `/v1/reports/${reportId}/export?format=json`, {
    headers,
  });
  expectStatus(exported, 200, `GET /v1/reports/${reportId}/export?format=json`);
  const exportVerdict = (exported.json?.payload?.verdicts ?? []).find(
    (entry) => entry.test_run_id === runId,
  );
  if (!exportVerdict) {
    throw new Error(`GET /v1/reports/${reportId}/export expected verdict for ${runId}`);
  }
  if (exported.json?.custody?.artifact_type !== 'report_export' || !exported.json?.custody?.content_sha256) {
    throw new Error(`GET /v1/reports/${reportId}/export expected report_export custody manifest`);
  }
  checks.push('report_export_custody');

  return {
    checks,
    run_id: runId,
    report_id: reportId,
    verdict: detail.json.verdict.verdict,
  };
}

/**
 * @param {string} baseUrl
 * @param {Record<string, string>} [authHeaders]
 */
export async function runLocalStagingSmoke(
  baseUrl = DEFAULT_LOCAL_STAGING_BASE_URL,
  authHeaders,
) {
  const checks = [];

  const health = await stagingFetch(baseUrl, '/health');
  if (health.status !== 200 || health.json?.status !== 'ok') {
    throw new Error(`GET /health expected 200 ok (got ${health.status})`);
  }
  checks.push('health');

  const ready = await stagingFetch(baseUrl, '/ready');
  if (ready.status !== 200) {
    throw new Error(`GET /ready expected 200 (got ${ready.status})`);
  }
  checks.push('ready');

  const headers = authHeaders
    ?? await resolveStagingAuthHeaders(baseUrl, { authMode: ready.json?.auth_mode });
  const checksApi = await stagingFetch(baseUrl, '/v1/checks', { headers });
  expectStatus(checksApi, 200, 'GET /v1/checks');
  const catalogItems = expectArrayResponse(checksApi, 'GET /v1/checks', ['checks', 'items']);
  // The customer-selectable catalog intentionally withholds checks that need extra run-time
  // input (host_sni_bypass profiles, declared probe paths) so the
  // portal never offers a check that would immediately error. Assert both halves of that
  // contract: a selectable check is present, and a gated one is absent.
  if (!catalogItems.some((entry) => entry.check_id === SMOKE_CHECK_ID)) {
    throw new Error(`GET /v1/checks expected ${SMOKE_CHECK_ID} in catalog`);
  }
  if (catalogItems.some((entry) => entry.check_id === 'origin.direct_bypass.safe')) {
    throw new Error('GET /v1/checks must not offer origin.direct_bypass.safe: it requires additional run-time input');
  }
  checks.push('checks_catalog');

  const targetGroups = await stagingFetch(baseUrl, '/v1/target-groups', { headers });
  expectStatus(targetGroups, 200, 'GET /v1/target-groups');
  const groupItems = expectArrayResponse(targetGroups, 'GET /v1/target-groups', ['target_groups', 'items']);
  checks.push('target_groups_list');

  const demoGroup = groupItems.find(
    (entry) => entry.id === LOCAL_STAGING_DEMO_IDS.targetGroupId,
  );
  if (!demoGroup) {
    throw new Error('Seeded demo target group tg_demo_origin not found; run seed-local-staging-tenant');
  }
  checks.push('seeded_target_group');

  const state = await stagingFetch(baseUrl, '/v1/state', { headers });
  if (state.status !== 200) {
    throw new Error(`GET /v1/state expected 200 (got ${state.status})`);
  }
  checks.push('state_summary');

  const validationLoop = await runLocalStagingValidationLoopSmoke(baseUrl, headers);
  checks.push(...validationLoop.checks);

  return {
    checks,
    persistence_mode: ready.json?.persistence_mode ?? ready.json?.persistence ?? null,
    probe_mode: ready.json?.probe_mode ?? null,
    auth_mode: ready.json?.auth_mode ?? null,
    validation_loop: validationLoop,
  };
}

async function main() {
  const baseUrl = String(process.env.ASTRANULL_LOCAL_STAGING_BASE_URL ?? DEFAULT_LOCAL_STAGING_BASE_URL).trim();
  try {
    const result = await runLocalStagingSmoke(baseUrl);
    console.log(`local-staging-smoke: ok (${result.checks.join(', ')})`);
    if (result.persistence_mode) {
      console.log(`  persistence_mode: ${result.persistence_mode}`);
    }
    if (result.probe_mode || result.auth_mode) {
      console.log(`  local_mode: auth=${result.auth_mode ?? 'unknown'} probe=${result.probe_mode ?? 'unknown'}`);
    }
    if (result.validation_loop) {
      console.log(
        `  safe_validation_loop: run=${result.validation_loop.run_id} verdict=${result.validation_loop.verdict} report=${result.validation_loop.report_id}`,
      );
    }
    console.log('  note: local staging smoke uses dev headers and safe probe simulation; it is not production promotion signoff.');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`local-staging-smoke: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main();
}
