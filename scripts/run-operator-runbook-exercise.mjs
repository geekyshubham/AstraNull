#!/usr/bin/env node
/**
 * Executes operator runbook health checks against a live control plane and writes evidence.
 */
import { execSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildDefaultOperatorRunbookEvidence,
  createOperatorRunbookEvidenceArtifact,
} from './operator-runbook-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

function parseArgs(argv = []) {
  const opts = {
    baseUrl: process.env.ASTRANULL_HOSTED_STAGING_BASE_URL
      ?? process.env.ASTRANULL_LOCAL_STAGING_BASE_URL
      ?? 'http://127.0.0.1:3000',
    releaseId: process.env.ASTRANULL_RELEASE_ID ?? 'rel-hosted-staging-2026-07-03',
    environment: 'staging',
    out: path.join(REPO_ROOT, 'output/release-evidence/operator-runbook-exercise-input.json'),
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => argv[++i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--environment') opts.environment = next();
    else if (arg === '--out') opts.out = next();
  }
  return opts;
}

async function probe(baseUrl, pathname) {
  const response = await fetch(new URL(pathname, baseUrl));
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json, text };
}

export async function runOperatorRunbookExercise(opts) {
  const baseUrl = String(opts.baseUrl).replace(/\/$/, '');
  const startedAt = new Date().toISOString();
  const steps = [];

  const health = await probe(baseUrl, '/health');
  steps.push({ step: 'health', ok: health.status === 200 && health.json?.status === 'ok' });
  const ready = await probe(baseUrl, '/ready');
  steps.push({
    step: 'ready',
    ok: ready.status === 200 && ready.json?.status === 'ready',
  });
  const metrics = await probe(baseUrl, '/metrics');
  steps.push({ step: 'metrics', ok: metrics.status === 200 && /test_runs_started_total/.test(metrics.text ?? '') });

  let tenantAuditOk = false;
  try {
    execSync('node scripts/postgres-tenant-query-audit.mjs', { cwd: REPO_ROOT, stdio: 'pipe' });
    tenantAuditOk = true;
  } catch {
    tenantAuditOk = false;
  }
  steps.push({ step: 'postgres_tenant_query_audit', ok: tenantAuditOk });

  const failed = steps.filter((step) => !step.ok);
  if (failed.length > 0) {
    throw new Error(`Operator runbook exercise failed: ${failed.map((s) => s.step).join(', ')}`);
  }

  const evidence = buildDefaultOperatorRunbookEvidence({
    environment: opts.environment,
    releaseId: opts.releaseId,
    createdAt: startedAt,
    exerciseEndAt: new Date().toISOString(),
    operator: 'release-manager',
    runbookVersion: '2026-07-04',
    evidence_uri: `evidence://runbook/${opts.environment}-exercise-live`,
    signoff_reference: `signoff://ops-security/${opts.environment}-live`,
  });

  const artifact = createOperatorRunbookEvidenceArtifact({
    evidence,
    releaseId: opts.releaseId,
    createdAt: startedAt,
  });
  if (!artifact.validation.ok) {
    throw new Error('Operator runbook evidence failed contract validation');
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(evidence, null, 2)}\n`);
  return { evidence, artifact, steps, out: opts.out };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/run-operator-runbook-exercise.mjs [--base-url URL] [--release-id rel]');
    return 0;
  }
  const result = await runOperatorRunbookExercise(opts);
  console.log(`run-operator-runbook-exercise: ok (${result.steps.length} steps) wrote ${result.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`run-operator-runbook-exercise: ${err.message}`);
      process.exit(1);
    },
  );
}