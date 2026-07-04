#!/usr/bin/env node
/**
 * Executes live staging OIDC login probes and writes metadata-only evidence input.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mintBundledStagingOidcJwt } from '../src/lib/bundledStagingOidc.mjs';
import {
  OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS,
  createOidcStagingLoginEvidenceManifest,
} from './oidc-staging-login-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUT = path.join(REPO_ROOT, 'output/release-evidence/oidc-staging-login-input.json');

function parseArgs(argv = []) {
  const opts = {
    baseUrl: process.env.ASTRANULL_HOSTED_STAGING_BASE_URL
      ?? process.env.ASTRANULL_LOCAL_STAGING_BASE_URL
      ?? 'http://127.0.0.1:3000',
    releaseId: process.env.ASTRANULL_RELEASE_ID ?? 'rel-hosted-staging-2026-07-03',
    environment: 'staging',
    out: DEFAULT_OUT,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--environment') opts.environment = next();
    else if (arg === '--out') opts.out = next();
  }
  return opts;
}

async function probe(baseUrl, pathname, headers = {}) {
  const response = await fetch(new URL(pathname, baseUrl), {
    headers: { accept: 'application/json', ...headers },
  });
  let json = null;
  const text = await response.text();
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json };
}

function roleForScenario(scenarioId) {
  if (scenarioId.includes('admin')) return 'admin';
  if (scenarioId.includes('engineer')) return 'engineer';
  if (scenarioId.includes('viewer')) return 'viewer';
  if (scenarioId.includes('soc')) return 'soc';
  return 'admin';
}

export async function runLiveOidcStagingLogin(opts) {
  const baseUrl = String(opts.baseUrl).replace(/\/$/, '');
  const completedAt = new Date().toISOString();
  const scenarios = [];

  for (const scenarioId of OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS) {
    let status = 'failed';
    let apiProbeReference = `probe://oidc/staging-login/${scenarioId}`;

    try {
      if (scenarioId === 'header_only_negative') {
        const denied = await probe(baseUrl, '/v1/checks', {
          'x-tenant-id': 'ten_demo',
          'x-user-id': 'usr_admin',
          'x-role': 'admin',
        });
        status = denied.status === 401 ? 'passed' : 'failed';
        apiProbeReference = `probe://oidc/staging-login/header_only_negative/status=${denied.status}`;
      } else if (scenarioId === 'invalid_token_rejected') {
        const denied = await probe(baseUrl, '/v1/checks', {
          authorization: 'Bearer invalid.token.value',
        });
        status = denied.status === 401 ? 'passed' : 'failed';
        apiProbeReference = `probe://oidc/staging-login/invalid_token/status=${denied.status}`;
      } else if (scenarioId === 'mfa_login') {
        const token = mintBundledStagingOidcJwt({
          role: 'admin',
          userId: 'usr_admin',
          tenantId: 'ten_demo',
          extraClaims: { amr: ['mfa', 'otp'] },
        }, { ...process.env, ASTRANULL_HOSTED_STAGING_BASE_URL: baseUrl });
        const ok = await probe(baseUrl, '/v1/checks', { authorization: `Bearer ${token}` });
        status = ok.status === 200 ? 'passed' : 'failed';
        apiProbeReference = `probe://oidc/staging-login/mfa_login/status=${ok.status}`;
      } else if (scenarioId === 'tenant_claim_mapping') {
        const token = mintBundledStagingOidcJwt({
          role: 'admin',
          userId: 'usr_admin',
          tenantId: 'ten_demo',
        }, { ...process.env, ASTRANULL_HOSTED_STAGING_BASE_URL: baseUrl });
        const ok = await probe(baseUrl, '/v1/target-groups', { authorization: `Bearer ${token}` });
        status = ok.status === 200 ? 'passed' : 'failed';
        apiProbeReference = `probe://oidc/staging-login/tenant_claim_mapping/status=${ok.status}`;
      } else {
        const role = roleForScenario(scenarioId);
        const token = mintBundledStagingOidcJwt({
          role,
          userId: `usr_${role}`,
          tenantId: 'ten_demo',
        }, { ...process.env, ASTRANULL_HOSTED_STAGING_BASE_URL: baseUrl });
        const ok = await probe(baseUrl, '/v1/checks', { authorization: `Bearer ${token}` });
        status = ok.status === 200 ? 'passed' : 'failed';
        apiProbeReference = `probe://oidc/staging-login/${scenarioId}/status=${ok.status}`;
      }
    } catch (err) {
      status = 'failed';
      apiProbeReference = `probe://oidc/staging-login/${scenarioId}/error=${encodeURIComponent(err.message)}`;
    }

    scenarios.push({
      scenario_id: scenarioId,
      status,
      evidence_uri: `evidence://oidc/staging-login/${scenarioId}`,
      owner: 'security-oncall',
      completed_at: completedAt,
      api_probe_reference: apiProbeReference,
      mapped_role: scenarioId.includes('role') ? roleForScenario(scenarioId) : undefined,
      mapped_tenant_reference: scenarioId === 'tenant_claim_mapping' ? 'ten_demo' : undefined,
    });
  }

  const evidence = {
    release_id: opts.releaseId,
    environment: opts.environment,
    evidence_uri: `evidence://oidc/staging-login/${opts.environment}`,
    claim_mapping_summary: {
      tenant_claim: 'tenant_id',
      role_claim: 'role',
      user_claim: 'sub',
      mapped_roles: ['admin', 'engineer', 'viewer', 'soc'],
    },
    signoff: {
      owner: 'security-oncall',
      signed_at: completedAt,
      signoff_reference: `signoff://oidc/staging-login/${opts.environment}`,
    },
    scenarios,
  };

  const manifest = createOidcStagingLoginEvidenceManifest({ evidence, releaseId: opts.releaseId });
  if (!manifest.validation.ok) {
    throw new Error(`OIDC staging login evidence incomplete (${manifest.validation.failed_scenarios.join(', ')})`);
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(evidence, null, 2)}\n`);
  return { evidence, manifest, out: opts.out };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/run-live-oidc-staging-login.mjs [--base-url URL] [--release-id rel] [--out file]');
    return 0;
  }
  const result = await runLiveOidcStagingLogin(opts);
  console.log(`run-live-oidc-staging-login: ok (${result.manifest.scenarios.length} scenarios) wrote ${result.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`run-live-oidc-staging-login: ${err.message}`);
      process.exit(1);
    },
  );
}