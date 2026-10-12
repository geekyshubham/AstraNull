import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { signProbeJob } from '../../src/lib/probeJobs.mjs';
import { authenticateProbeWorker } from '../../src/services/probeCoordinator.mjs';
import { pollAndProcessOnce } from '../../workers/probe-worker.mjs';

const secret = 'batch-continuation-worker-secret-at-least-32';
const tenantId = 'ten_batch_continuation';
const workerId = 'worker_batch_continuation';

async function fixture(t, rejectionStatus) {
  const issuedAt = Date.now();
  const jobs = Array.from({ length: 8 }, (_, index) => {
    const targetId = index === 1 ? 'target_0' : `target_${index}`;
    const job = {
      id: `job_${index}`, tenant_id: tenantId, test_run_id: `run_${index}`,
      target_id: targetId, check_id: 'fixture.unsupported.safe', nonce_hash: 'a'.repeat(64),
      target: { id: targetId, kind: 'url', value: 'https://never-contact.example.test/diagnostic' },
      leased_at: new Date(issuedAt).toISOString(), leased_by: workerId,
      probe_profile: { kind: 'fixture_unsupported_kind', timeout_ms: 100, max_requests: 1 },
      constraints: {
        authority_version: 'probe-authority-v2', issued_at: new Date(issuedAt).toISOString(),
        not_after: new Date(issuedAt + 120_000).toISOString(), execution_attempts: 1,
        timeout_ms: 100, max_requests: 3, max_probe_requests: 1,
        min_destination_resolver_attempts: 2, max_destination_resolver_attempts: 2, max_total_operations: 3,
      },
    };
    job.job_signature = signProbeJob(job, secret);
    return job;
  });
  const reservations = [], results = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const bodyText = Buffer.concat(chunks).toString('utf8');
    const auth = authenticateProbeWorker(req.headers, req.method, req.url, bodyText,
      { probeMode: 'signed-worker', probeWorkerSecret: secret });
    if (!auth.ok || auth.workerCtx.tenantId !== tenantId || auth.workerCtx.workerId !== workerId) {
      res.writeHead(401).end();
      return;
    }
    res.setHeader('content-type', 'application/json');
    if (req.method === 'GET' && req.url === '/internal/probe/jobs') {
      res.end(JSON.stringify({ jobs }));
      return;
    }
    const match = req.url.match(/^\/internal\/probe\/jobs\/(job_\d+)\/(execute|activity|result)$/);
    if (!match) { res.writeHead(404).end(); return; }
    const job = jobs.find((entry) => entry.id === match[1]);
    const body = JSON.parse(bodyText);
    if (match[2] === 'execute') {
      assert.equal(body.leased_at, job.leased_at);
      reservations.push(job.id);
      res.writeHead(201).end(JSON.stringify({ authorized: true, reservation_id: `reservation_${job.id}`,
        not_after: job.constraints.not_after }));
    } else if (match[2] === 'activity') {
      res.writeHead(201).end(JSON.stringify({ continue: true }));
    } else {
      results.push({ id: job.id, body });
      res.writeHead(job.id === 'job_0' ? rejectionStatus : 201).end(JSON.stringify({ error: 'fixture_rejection' }));
    }
  });
  server.on('error', (error) => { throw error; });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return {
    jobs, reservations, results,
    config: { apiUrl: `http://127.0.0.1:${server.address().port}`, workerId, tenantId, secret },
  };
}

for (const status of [400, 404, 409, 422]) {
  test(`terminal per-job ${status} rejection does not strand later waves or same-target queued checks`, async (t) => {
    const { jobs, reservations, results, config } = await fixture(t, status);
    const output = await pollAndProcessOnce(config);
    assert.equal(output.length, jobs.length);
    assert.equal(output.find((entry) => entry.job_id === 'job_0').rejected, status);
    assert.equal(reservations.length, jobs.length, 'exactly one reservation per job');
    assert.equal(results.length, jobs.length, 'exactly one result post per job');
    assert.deepEqual(new Set(reservations), new Set(jobs.map((job) => job.id)));
    assert.deepEqual(new Set(results.map((entry) => entry.id)), new Set(jobs.map((job) => job.id)));
    for (const { body } of results) {
      assert.equal(body.external_result, 'error');
      assert.equal(body.metadata.error_class, 'unsupported_probe_kind');
      assert.equal(body.safety_attestation.requests_sent, 0);
      assert.equal(body.safety_attestation.destination_resolver_attempts, 0);
    }
  });
}

for (const status of [401, 403, 429, 500]) {
  test(`control-plane ${status} failure stops later waves rather than silently continuing destination work`, async (t) => {
    const { reservations, config } = await fixture(t, status);
    await assert.rejects(pollAndProcessOnce(config), new RegExp(`Probe result post failed \\(${status}\\)`));
    assert.equal(reservations.length, 4);
    assert.equal(reservations.includes('job_1'), false, 'same-target second check has not started');
    assert.equal(reservations.includes('job_7'), false, 'later wave has not started');
  });
}
