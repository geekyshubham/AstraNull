#!/usr/bin/env node
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync } from 'node:fs';
import { isIP } from 'node:net';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../..');

const HARNESS_PORT = process.env.ANL_HARNESS_PORT ?? '3011';
const API_BASE = `http://127.0.0.1:${HARNESS_PORT}`;
const TENANT_ID = process.env.ANL_HARNESS_TENANT ?? 'ten_anl_harness';
const WORKER_SECRET = 'anl-harness-worker-probe-secret-entropy-32c!';
const WORKER_NAME = process.env.ANL_HARNESS_WORKER ?? 'anl-harness-probe-worker';
const HEADERS = {
  'content-type': 'application/json',
  'x-tenant-id': TENANT_ID,
  'x-user-id': 'usr_anl_harness',
  'x-role': 'admin',
};

function printUsage() {
  console.log(`Usage: run-checks.sh --manifest <path> [--checks id1,id2 | --prefix waf.] --out <dir>

Options:
  --manifest <path>     Path to the lab manifest.json (required)
  --checks <id1,id2>    Comma-separated list of check IDs to run (optional)
  --prefix <prefix>     Check ID prefix to filter by, e.g. waf. (optional)
  --out <dir>           Output directory for results.jsonl and summary.md (required)
  --help, -h            Show this help message and exit
`);
}

export function parseArgs(argv) {
  const args = {
    manifest: null,
    checks: null,
    prefix: null,
    out: null,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    }
    if (arg === '--manifest') {
      args.manifest = argv[++i];
    } else if (arg === '--checks') {
      args.checks = argv[++i]?.split(',').map((s) => s.trim()).filter(Boolean);
    } else if (arg === '--prefix') {
      args.prefix = argv[++i]?.trim();
    } else if (arg === '--out') {
      args.out = argv[++i];
    }
  }

  if (!args.manifest) {
    console.error('Error: --manifest <path> is required');
    printUsage();
    process.exit(1);
  }
  if (!args.out) {
    console.error('Error: --out <dir> is required');
    printUsage();
    process.exit(1);
  }

  return args;
}

export function validateNetworkName(net) {
  return typeof net === 'string' && /^anl-[a-z0-9-]+-(net|client|server)$/.test(net);
}

export function validateAddress(addr) {
  if (typeof addr !== 'string') return false;
  const family = isIP(addr);
  if (family === 4) {
    const ipv4Match = /^172\.31\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
    if (!ipv4Match) return false;
    const b = Number(ipv4Match[1]);
    const c = Number(ipv4Match[2]);
    return b >= 0 && b <= 255 && c >= 0 && c <= 255;
  }
  if (family === 6) {
    return addr.toLowerCase().startsWith('fd00:a57a:');
  }
  return false;
}

export function validateHostname(host) {
  if (host === null || host === undefined) return true;
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) return false;
  if (/[/@:\s\\?#]/.test(host)) return false;
  if (host !== 'lab.efficacy.invalid' && !host.endsWith('.lab.efficacy.invalid')) return false;
  const labels = host.split('.');
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) return false;
  }
  return true;
}

export function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('Invalid manifest: must be an object');
  }
  for (const net of manifest.networks ?? []) {
    if (!validateNetworkName(net)) {
      throw new Error(`Invalid network name "${net}": must match /^anl-[a-z0-9-]+-(net|client|server)$/`);
    }
  }
  if (!Array.isArray(manifest.targets) || manifest.targets.length === 0) {
    throw new Error('Manifest must have at least one target');
  }
  for (const target of manifest.targets) {
    const isAllNA = Array.isArray(target.expectations) &&
      target.expectations.length > 0 &&
      target.expectations.every((e) => String(e.expected || '').toLowerCase() === 'not_applicable');

    if (target.network && Array.isArray(manifest.networks) && !manifest.networks.includes(target.network)) {
      if (!isAllNA) {
        throw new Error(`Target network "${target.network}" is not in manifest networks`);
      }
    }

    const isPermittedAddr = (addr) => {
      if (validateAddress(addr)) return true;
      if (isAllNA && (addr === '127.0.0.1' || addr === '::1' || addr === 'localhost')) return true;
      return false;
    };

    if (target.address && !isPermittedAddr(target.address)) {
      throw new Error(`Rejected arbitrary/public address "${target.address}": must be 172.31.0.0/16 or fd00:a57a:*`);
    }
    if (Array.isArray(target.addresses)) {
      for (const addr of target.addresses) {
        if (!isPermittedAddr(addr)) {
          throw new Error(`Rejected arbitrary/public address "${addr}": must be 172.31.0.0/16 or fd00:a57a:*`);
        }
      }
    }
    if (target.hostname && !validateHostname(target.hostname)) {
      throw new Error(`Rejected non-synthetic hostname "${target.hostname}": exact lab synthetic only (*.lab.efficacy.invalid)`);
    }
  }
  return true;
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

export function isSafetyRefused(checkId, probeProfile) {
  const lower = String(checkId || '').toLowerCase();
  if (/(offensive|high_scale|flood|slowloris|volumetric|memcached_stats|monlist)/i.test(lower)) {
    return true;
  }
  const kind = String(probeProfile?.kind ?? '').toLowerCase();
  if (/(volumetric|flood|slowloris|high_scale)/i.test(kind)) {
    return true;
  }
  return false;
}

export function normalizeVerdict(verdictStr) {
  if (!verdictStr) return 'inconclusive';
  const val = String(verdictStr).toLowerCase().trim();
  if (['exposed', 'edge_exposed', 'gap'].includes(val)) return 'gap';
  if (['protected', 'edge_protected', 'allowed_as_expected'].includes(val)) return 'protected';
  if (['inconclusive', 'withheld', 'indeterminate'].includes(val)) return 'inconclusive';
  return val;
}

export function gradeResult(expected, actualVerdict, outcome, runStatus) {
  const normExpected = String(expected || '').toLowerCase().trim();
  const normActual = normalizeVerdict(actualVerdict);
  const normOutcome = String(outcome || '').toLowerCase().trim();
  const normStatus = String(runStatus || '').toLowerCase().trim();

  const isTerminalSuccess = normStatus === 'verdicted' || normStatus === 'completed';
  const isRunnerOrSystemFailure =
    normOutcome === 'runner_timeout' ||
    normOutcome === 'dispatch_rejected' ||
    normOutcome === 'unknown_check' ||
    normOutcome === 'target_resolution_failed' ||
    normOutcome === 'error' ||
    normOutcome === 'execution_error' ||
    normStatus === 'failed' ||
    normStatus === 'cancelled' ||
    normOutcome === 'cancelled' ||
    normActual === 'execution_error' ||
    normActual === 'error' ||
    normActual === 'failed' ||
    (!isTerminalSuccess && normOutcome === 'timeout') ||
    (!isTerminalSuccess && ['running', 'planned', 'collecting'].includes(normStatus));

  if (isRunnerOrSystemFailure) {
    return 'execution_error';
  }

  if (normActual === 'skipped_safety' || normOutcome === 'skipped_safety') {
    return 'skipped_safety';
  }
  if (normExpected === 'not_applicable') {
    return 'not_applicable';
  }
  if (normActual === 'inconclusive') {
    return 'inconclusive';
  }
  if (normExpected === 'inconclusive_expected') {
    return normActual === 'inconclusive' ? 'inconclusive' : (normActual === 'gap' ? 'false alarm' : 'correct protected');
  }
  if (normExpected === 'gap') {
    if (normActual === 'gap') return 'detected gap';
    if (normActual === 'protected') return 'missed gap';
    return 'inconclusive';
  }
  if (normExpected === 'protected') {
    if (normActual === 'protected') return 'correct protected';
    if (normActual === 'gap') return 'false alarm';
    return 'inconclusive';
  }
  return 'inconclusive';
}

export function declaredTargetPort(targetDecl, checkDef) {
  const checkId = checkDef?.check_id ?? '';
  const netPolicies = targetDecl?.declarations?.network_policy ?? [];
  const declaredTcpDeny = netPolicies.find(
    (p) => (!p.protocol || p.protocol === 'tcp') && p.action === 'deny'
  )?.port;
  const declaredConnLimit = targetDecl?.declarations?.connection_limits?.[0]?.port;
  const declaredUdpDeny = netPolicies.find(
    (p) => p.protocol === 'udp' && p.action === 'deny'
  )?.port;

  if (checkId === 'nfw.declared_deny_tcp.safe' || checkId === 'l3.basic_deny_rule.safe') {
    return declaredTcpDeny;
  }
  if (checkId.includes('connection_limit')) {
    return declaredConnLimit;
  }
  if (checkId.includes('deny_udp') || checkId.includes('udp_deny')) {
    return declaredUdpDeny;
  }
  return declaredTcpDeny ?? declaredConnLimit ?? declaredUdpDeny ?? undefined;
}

export function resolveTargetSpec(targetDecl, checkDef) {
  const supported = checkDef?.supported_targets ?? ['url', 'fqdn', 'ip'];
  const address = targetDecl.address;
  const hostname = targetDecl.hostname;
  const decPort = declaredTargetPort(targetDecl, checkDef);

  if (supported.includes('tcp') && decPort !== undefined) {
    const host = hostname || address;
    const hostPart = host && host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    return { kind: 'tcp', value: `${hostPart}:${decPort}` };
  }

  const hostPart = hostname || (address && address.includes(':') && !address.startsWith('[') ? `[${address}]` : address);
  const httpPort = targetDecl.ports?.find((p) => p.service === 'http' || p.port === 80 || p.port === 8080)?.port ?? 80;
  const httpsPort = targetDecl.ports?.find((p) => p.service === 'https' || p.port === 443)?.port;

  if (supported.includes('url')) {
    if (httpsPort) {
      return { kind: 'url', value: `https://${hostPart}${httpsPort === 443 ? '' : `:${httpsPort}`}/` };
    }
    return { kind: 'url', value: `http://${hostPart}${httpPort === 80 ? '' : `:${httpPort}`}/` };
  }

  if (hostname && (supported.includes('fqdn') || supported.includes('dns'))) {
    return { kind: 'fqdn', value: hostname };
  }

  if (supported.includes('ip') && address) {
    return { kind: 'ip', value: address };
  }

  if (supported.includes('tcp')) {
    const tcpPort = targetDecl.ports?.find((p) => p.protocol === 'tcp')?.port ?? 80;
    const host = hostname || address;
    const hostStr = host && host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    return { kind: 'tcp', value: `${hostStr}:${tcpPort}` };
  }

  if (supported.includes('fqdn') || supported.includes('dns')) {
    return { kind: 'fqdn', value: hostname ?? 'lab.efficacy.invalid' };
  }

  return { kind: 'url', value: `http://${hostPart}/` };
}

export function extractSafeProbeMetadata(probeMetadata, events) {
  let raw = (probeMetadata && typeof probeMetadata === 'object' && Object.keys(probeMetadata).length > 0)
    ? probeMetadata
    : null;

  const eventList = Array.isArray(events)
    ? events
    : (Array.isArray(events?.items) ? events.items : []);

  if (!raw && eventList.length > 0) {
    const probeEv = eventList.find((e) => e?.signal_type === 'probe_result');
    if (probeEv?.metadata && typeof probeEv.metadata === 'object') {
      raw = probeEv.metadata;
    } else if (typeof probeEv?.metadata_json === 'string') {
      try {
        raw = JSON.parse(probeEv.metadata_json);
      } catch {}
    } else if (probeEv?.metadata_json && typeof probeEv.metadata_json === 'object') {
      raw = probeEv.metadata_json;
    }
  }

  if (!raw && eventList.length === 0) return undefined;

  const safe = {};
  const allowedKeys = [
    'error_class', 'inconclusive_reason', 'not_run_reason', 'comparison_reason',
    'profile_kind', 'probe_kind', 'enforcement', 'complete', 'tls_issues',
    'days_to_expiry', 'valid_to', 'certificate_not_yet_valid', 'max_concurrent_streams',
    'nameserver_count', 'nameserver_count_below_two', 'nameservers', 'axfr_leak',
    'axfr_refused', 'nameservers_total', 'nameservers_queried', 'unqueried_nameservers',
    'tcp_outcome', 'udp_outcome', 'parity', 'port', 'address_family', 'sample_agreement',
    'planned_marker_legs', 'completed_marker_legs', 'graded_marker_legs',
    'ungraded_marker_legs', 'requests_sent', 'duration_ms', 'external_result',
    'rtt_ms', 'latency_ms', 'dns_rcode', 'dns_flags', 'dns_answers_count',
    'tls_version', 'cipher', 'status_code', 'protocol', 'alpn',
    'stream_concurrency', 'handshake_time_ms', 'error_code', 'timeout',
    'attempt_count', 'bytes_transferred'
  ];

  if (raw) {
    for (const k of allowedKeys) {
      if (raw[k] !== undefined) {
        safe[k] = raw[k];
      }
    }

    if (Array.isArray(raw.placements)) {
      safe.placements = raw.placements.slice(0, 16).map((p) => ({
        placement: p.placement,
        outcome: p.outcome,
        status_code: p.status_code,
        inconclusive_reason: p.inconclusive_reason,
      }));
    }

    if (Array.isArray(raw.nameserver_results)) {
      safe.nameserver_results = raw.nameserver_results.slice(0, 16).map((nr) => ({
        nameserver: nr.nameserver,
        address: nr.address,
        queried: nr.queried,
        axfr_leak: nr.axfr_leak,
        axfr_refused: nr.axfr_refused,
        rcode: nr.rcode,
        reason: nr.reason,
      }));
    }

    if (Array.isArray(raw.port_results)) {
      safe.port_results = raw.port_results.slice(0, 16).map((pr) => {
        const res = {
          port: pr.port,
          protocol: pr.protocol,
          outcome: pr.outcome ?? pr.tcp_outcome ?? pr.udp_outcome,
        };
        if (pr.tcp_outcome !== undefined) res.tcp_outcome = pr.tcp_outcome;
        if (pr.udp_outcome !== undefined) res.udp_outcome = pr.udp_outcome;
        const sampleCount = Array.isArray(pr.samples)
          ? pr.samples.length
          : (typeof pr.sample_count === 'number' ? pr.sample_count : (typeof pr.count === 'number' ? pr.count : undefined));
        if (sampleCount !== undefined) res.sample_count = sampleCount;
        return res;
      });
    }

    if (raw.families && typeof raw.families === 'object' && !Array.isArray(raw.families)) {
      safe.families = {};
      for (const [k, f] of Object.entries(raw.families)) {
        if (!f || typeof f !== 'object') continue;
        const fam = {};
        for (const field of ['tcp_outcome', 'udp_outcome', 'port', 'address_family', 'sample_agreement']) {
          if (f[field] !== undefined) fam[field] = f[field];
        }
        if (Array.isArray(f.samples)) {
          fam.sample_count = f.samples.length;
        } else if (typeof f.sample_count === 'number') {
          fam.sample_count = f.sample_count;
        }
        safe.families[k] = fam;
      }
    } else if (Array.isArray(raw.families)) {
      safe.families = raw.families.slice(0, 16).map((f) => ({
        address_family: f.address_family ?? f.family,
        outcome: f.outcome ?? f.tcp_outcome ?? f.udp_outcome,
        sample_count: Array.isArray(f.samples) ? f.samples.length : (typeof f.sample_count === 'number' ? f.sample_count : undefined),
      }));
    }

    if (raw.safety_attestation && typeof raw.safety_attestation === 'object') {
      const sa = raw.safety_attestation;
      safe.safety_attestation = {};
      for (const f of ['requests_sent', 'probe_requests_sent', 'destination_resolver_attempts', 'total_operations', 'duration_ms']) {
        if (sa[f] !== undefined) safe.safety_attestation[f] = sa[f];
      }
    }
  }

  if (eventList.length > 0) {
    safe.event_count = eventList.length;
    const placementEvents = eventList.filter((e) => e.placement || e.event_type === 'placement_observation');
    if (placementEvents.length > 0) {
      safe.placement_observations = placementEvents.length;
    }
    const attestations = eventList.filter((e) => e.event_type?.includes('attestation') || e.attestation);
    if (attestations.length > 0) {
      safe.attestation_count = attestations.length;
    }
  }

  return Object.keys(safe).length > 0 ? safe : undefined;
}

async function ensureApiRunning() {
  for (let i = 0; i < 20; i++) {
    try {
      const res = await fetch(`${API_BASE}/ready`, { signal: AbortSignal.timeout(500) });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.status === 'ready') {
        console.log(`Control plane API already running and ready on port ${HARNESS_PORT}`);
        return { proc: null, started: false };
      }
      if (data.reason === 'draining') {
        console.log('Waiting for previous draining API to finish exiting...');
        await sleep(1000);
        continue;
      }
    } catch {
      break;
    }
  }

  console.log(`Starting AstraNull control plane on 127.0.0.1:${HARNESS_PORT}...`);
  const env = {
    ...process.env,
    PORT: HARNESS_PORT,
    ASTRANULL_PERSISTENCE_MODE: 'postgres',
    ASTRANULL_DATABASE_URL: 'postgresql://astranull_app:astranull_app_local_dev@127.0.0.1:54329/astranull',
    ASTRANULL_AUTH_MODE: 'dev-headers',
    ASTRANULL_PROBE_MODE: 'signed-worker',
    ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
    ASTRANULL_DEMO_AUTO_VERIFY_TENANTS: TENANT_ID,
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
    ASTRANULL_CONNECTORS_ENABLED: '0',
    NODE_ENV: 'development',
  };

  const proc = spawn('node', ['src/index.mjs'], {
    cwd: REPO_ROOT,
    env,
    stdio: 'ignore',
  });

  for (let i = 0; i < 30; i++) {
    await sleep(500);
    try {
      const res = await fetch(`${API_BASE}/ready`, { signal: AbortSignal.timeout(500) });
      if (res.ok) {
        console.log(`Control plane API is ready on port ${HARNESS_PORT}`);
        return { proc, started: true };
      }
    } catch {}
  }
  throw new Error(`AstraNull API failed to become ready on port ${HARNESS_PORT} within 15 seconds`);
}

async function cancelActiveRuns() {
  try {
    const listRes = await fetch(`${API_BASE}/v1/test-runs?limit=20`, {
      headers: HEADERS,
      signal: AbortSignal.timeout(5000),
    });
    if (!listRes.ok) return;
    const list = await listRes.json();
    for (const item of list.items ?? []) {
      if (['running', 'planned', 'collecting'].includes(item.status)) {
        console.log(`Cancelling previous active run ${item.id}...`);
        await fetch(`${API_BASE}/v1/test-runs/${item.id}/cancel`, {
          method: 'POST',
          headers: HEADERS,
          body: JSON.stringify({ reason: 'harness_reset' }),
          signal: AbortSignal.timeout(5000),
        }).catch(() => {});
      }
    }
  } catch {}
}

async function ensureWorkerRunning(networks = [], hasSyntheticDns = false) {
  console.log(`Starting signed probe worker container (${WORKER_NAME})...`);
  try {
    execFileSync('docker', ['rm', '-f', WORKER_NAME], { stdio: 'ignore' });
  } catch {}

  const dockerArgs = [
    'run', '-d',
    '--name', WORKER_NAME,
    '--restart', 'on-failure',
    '--network', 'anl-harness-net',
    '--cpus', '1.0',
    '--memory', '768m',
    '-e', 'NODE_ENV=development',
    '-e', 'ASTRANULL_PROBE_ALLOW_PRIVATE_DESTINATIONS=1',
    '-e', `ASTRANULL_PROBE_WORKER_SECRET=${WORKER_SECRET}`,
    '-e', `ASTRANULL_PROBE_TENANT_ID=${TENANT_ID}`,
    '-e', `ASTRANULL_API_URL=http://host.docker.internal:${HARNESS_PORT}`,
    '-e', 'ASTRANULL_PROBE_WORKER_ID=anl-harness-worker',
    '-e', 'ASTRANULL_PROBE_POLL_INTERVAL_MS=500',
    '-v', `${REPO_ROOT}:/app:ro`,
    '-w', '/app',
  ];

  if (hasSyntheticDns) {
    const answer = execFileSync('docker', ['exec', 'anl-harness-holder', 'getent', 'hosts', 'host.docker.internal'], { encoding: 'utf8' }).trim().split(/\s+/)[0];
    if (!isIP(answer)) {
      throw new Error(`Failed to resolve host.docker.internal: ${answer}`);
    }
    dockerArgs.push('--dns', '172.31.41.10', '--add-host', `host.docker.internal:${answer}`);
  }

  dockerArgs.push('node:22-alpine', 'node', 'workers/probe-worker.mjs');

  execFileSync('docker', dockerArgs, { stdio: 'ignore' });

  for (const net of networks) {
    if (net === 'anl-harness-net') continue;
    try {
      execFileSync('docker', ['network', 'connect', net, WORKER_NAME], { stdio: 'ignore' });
      console.log(`Connected probe worker to target network: ${net}`);
    } catch (err) {
      throw new Error(`Failed to connect probe worker to target network "${net}": ${err.message}`);
    }
  }

  await sleep(1000);
}

async function getOrCreateTarget(targetSpec) {
  const res = await fetch(`${API_BASE}/v1/targets`, {
    method: 'POST',
    headers: HEADERS,
    body: JSON.stringify(targetSpec),
    signal: AbortSignal.timeout(5000),
  });
  const data = await res.json();
  if (res.status === 201) return data.id;
  if (res.status === 409) return data.existing_id;

  const listRes = await fetch(`${API_BASE}/v1/targets`, {
    headers: HEADERS,
    signal: AbortSignal.timeout(5000),
  });
  const list = await listRes.json();
  const match = (list.items ?? []).find(
    (t) => t.kind === targetSpec.kind && (t.value === targetSpec.value || t.normalized_value === targetSpec.value)
  );
  return match?.id;
}

export async function applyControlDeclarations(targetId, declarations) {
  if (!declarations || Object.keys(declarations).length === 0) return;

  const wafDecl = declarations.waf ?? {};
  const sig = wafDecl.block_signature ?? declarations.waf_block_signature;
  if (sig) {
    if (sig.body_contains && !sig.header_name) {
      throw new Error('Unsupported signature diagnostic: body-only block declaration is not supported; header-based block_signature required');
    }
  }
  if (declarations.body_contains && !declarations.header_name) {
    throw new Error('Unsupported signature diagnostic: body-only block declaration is not supported; header-based block_signature required');
  }

  const body = { version: 1 };
  if (Array.isArray(declarations.network_policy)) {
    const allowedNetKeys = ['protocol', 'port', 'action', 'address_family', 'note'];
    body.network_policy = declarations.network_policy.map((p) => {
      const item = {};
      for (const k of allowedNetKeys) {
        if (p[k] !== undefined) item[k] = p[k];
      }
      return item;
    });
  }
  if (Array.isArray(declarations.connection_limits)) {
    body.connection_limits = declarations.connection_limits;
  }

  const waf = {};
  if (wafDecl.rate_limit_canary) {
    waf.rate_limit_canary = wafDecl.rate_limit_canary;
  }
  const expectedAction = wafDecl.expected_action ?? sig?.expected_action;
  if (expectedAction) {
    waf.expected_action = expectedAction;
  }
  if (sig && sig.header_name && sig.header_value) {
    const statusCodes = Array.isArray(sig.status_codes)
      ? sig.status_codes
      : sig.status
        ? [sig.status]
        : [403];
    waf.block_signature = {
      header_name: sig.header_name,
      header_value: sig.header_value,
      status_codes: statusCodes,
    };
  }
  if (Object.keys(waf).length > 0) {
    body.waf = waf;
  }

  if (Object.keys(body).length <= 1) return;

  const getRes = await fetch(`${API_BASE}/v1/targets/${targetId}/control-declarations`, {
    headers: HEADERS,
    signal: AbortSignal.timeout(5000),
  });
  const etag = getRes.headers.get('etag') || '"decl-r0"';

  const putRes = await fetch(`${API_BASE}/v1/targets/${targetId}/control-declarations`, {
    method: 'PUT',
    headers: { ...HEADERS, 'if-match': etag },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
  if (!putRes.ok) {
    const errText = await putRes.text().catch(() => '');
    throw new Error(`Failed to apply control declarations for target ${targetId}: HTTP ${putRes.status} ${errText}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = resolve(process.cwd(), args.manifest);
  if (!existsSync(manifestPath)) {
    console.error(`Error: Manifest file not found at ${manifestPath}`);
    process.exit(1);
  }

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  validateManifest(manifest);

  const outDir = resolve(process.cwd(), args.out);
  mkdirSync(outDir, { recursive: true });

  const jsonlPath = resolve(outDir, 'results.jsonl');
  writeFileSync(jsonlPath, '', 'utf8');

  console.log(`Loaded lab manifest: ${manifest.lab_id} (${manifestPath})`);

  const checksModule = await import(resolve(REPO_ROOT, 'src/contracts/checks.mjs'));
  const catalog = checksModule.CHECK_CATALOG ?? [];
  const catalogMap = new Map(catalog.map((c) => [c.check_id, c]));

  const hasSyntheticDns = (manifest.targets ?? []).some(
    (t) => t.hostname === 'lab.efficacy.invalid' || (typeof t.hostname === 'string' && t.hostname.endsWith('.lab.efficacy.invalid'))
  );
  const workerNetworks = [...(manifest.networks ?? [])];
  if (hasSyntheticDns && !workerNetworks.includes('anl-dns-lab-net')) {
    workerNetworks.push('anl-dns-lab-net');
  }

  let apiHandle = null;
  try {
    apiHandle = await ensureApiRunning();
    await cancelActiveRuns();
    await ensureWorkerRunning(workerNetworks, hasSyntheticDns);

    const results = [];
    const tally = {
      detected_gap: 0,
      missed_gap: 0,
      false_alarm: 0,
      correct_protected: 0,
      inconclusive: 0,
      not_applicable: 0,
      skipped_safety: 0,
      execution_error: 0,
    };
    const categorizedChecks = {
      detected_gap: [],
      missed_gap: [],
      false_alarm: [],
      correct_protected: [],
      inconclusive: [],
      not_applicable: [],
      skipped_safety: [],
      execution_error: [],
    };

    for (const targetDecl of manifest.targets ?? []) {
      console.log(`\nEvaluating target: ${targetDecl.name} (${targetDecl.address})`);

      for (const expectation of targetDecl.expectations ?? []) {
        let checkIds = [];
        if (expectation.check) {
          checkIds.push(expectation.check);
        } else if (expectation.check_prefix) {
          checkIds = catalog
            .filter((c) => c.check_id.startsWith(expectation.check_prefix))
            .map((c) => c.check_id);
        }

        if (args.checks && args.checks.length > 0) {
          checkIds = checkIds.filter((id) => args.checks.includes(id));
        }
        if (args.prefix) {
          checkIds = checkIds.filter((id) => id.startsWith(args.prefix));
        }

        for (const checkId of checkIds) {
          const checkDef = catalogMap.get(checkId);
          console.log(`\n[${manifest.lab_id}] Running check: ${checkId} (expected: ${expectation.expected})`);

          if (!checkDef) {
            console.error(`  -> Unknown check ID: ${checkId}`);
            const row = {
              target: targetDecl.name,
              check_id: checkId,
              expected: expectation.expected,
              why: expectation.why ?? '',
              verdict: 'execution_error',
              outcome: 'unknown_check',
              status: 'failed',
              grade: 'execution_error',
              evidence_summary: `Check ID "${checkId}" is not present in contract catalog`,
              run_id: null,
            };
            results.push(row);
            tally.execution_error++;
            categorizedChecks.execution_error.push(checkId);
            appendFileSync(jsonlPath, JSON.stringify(row) + '\n', 'utf8');
            continue;
          }

          if (String(expectation.expected || '').toLowerCase() === 'not_applicable') {
            console.log(`  -> Not applicable, not dispatched: ${checkId}`);
            const row = {
              target: targetDecl.name,
              check_id: checkId,
              expected: expectation.expected,
              why: expectation.why ?? '',
              verdict: 'not_applicable',
              outcome: 'not_applicable',
              status: 'skipped',
              grade: 'not_applicable',
              evidence_summary: expectation.why ?? 'Manifest marked this check not applicable',
              run_id: null,
            };
            results.push(row);
            tally.not_applicable++;
            categorizedChecks.not_applicable.push(checkId);
            appendFileSync(jsonlPath, JSON.stringify(row) + '\n', 'utf8');
            continue;
          }

          if (isSafetyRefused(checkId, checkDef?.probe_profile)) {
            console.log(`  -> Skipped by safety filter: ${checkId}`);
            const row = {
              target: targetDecl.name,
              check_id: checkId,
              expected: expectation.expected,
              why: expectation.why ?? 'Safety filter applied',
              verdict: 'skipped_safety',
              outcome: 'skipped_safety',
              status: 'skipped',
              grade: 'skipped_safety',
              evidence_summary: 'Hard filter: volumetric, attack, or high-scale checks are forbidden in efficacy lab contract',
              run_id: null,
            };
            results.push(row);
            tally.skipped_safety++;
            categorizedChecks.skipped_safety.push(checkId);
            appendFileSync(jsonlPath, JSON.stringify(row) + '\n', 'utf8');
            continue;
          }

          const targetSpec = resolveTargetSpec(targetDecl, checkDef);
          const targetId = await getOrCreateTarget(targetSpec);
          if (!targetId) {
            console.error(`  -> Failed to create/resolve target for ${checkId}`);
            const row = {
              target: targetDecl.name,
              check_id: checkId,
              expected: expectation.expected,
              why: expectation.why ?? '',
              verdict: 'execution_error',
              outcome: 'target_resolution_failed',
              status: 'failed',
              grade: 'execution_error',
              evidence_summary: 'Failed to create or resolve target specification',
              run_id: null,
            };
            results.push(row);
            tally.execution_error++;
            categorizedChecks.execution_error.push(checkId);
            appendFileSync(jsonlPath, JSON.stringify(row) + '\n', 'utf8');
            continue;
          }

          await applyControlDeclarations(targetId, targetDecl.declarations);

          const runPayload = {
            target_id: targetId,
            check_id: checkId,
          };

          let startRes = null;
          let startData = null;
          let runId = null;
          for (let attempt = 0; attempt < 12; attempt++) {
            startRes = await fetch(`${API_BASE}/v1/test-runs`, {
              method: 'POST',
              headers: HEADERS,
              body: JSON.stringify(runPayload),
              signal: AbortSignal.timeout(5000),
            });
            startData = await startRes.json();
            runId = startData.run?.id ?? startData.id;
            if (runId) break;
            if (startRes.status === 409 && startData.error === 'concurrent_run_blocked' && attempt < 11) {
              console.log(`  -> concurrent run still active, retry ${attempt + 1}`);
              await sleep(5000);
              continue;
            }
            break;
          }

          if (!runId) {
            console.warn(`  -> Test run dispatch failed (${startRes?.status}):`, startData);
            const row = {
              target: targetDecl.name,
              check_id: checkId,
              expected: expectation.expected,
              why: expectation.why ?? '',
              verdict: 'execution_error',
              outcome: 'dispatch_rejected',
              status: 'rejected',
              grade: 'execution_error',
              evidence_summary: startData?.error ?? 'Dispatch failed',
              run_id: null,
            };
            results.push(row);
            tally.execution_error++;
            categorizedChecks.execution_error.push(checkId);
            appendFileSync(jsonlPath, JSON.stringify(row) + '\n', 'utf8');
            continue;
          }

          const terminal = new Set(['verdicted', 'completed', 'failed', 'cancelled']);
          let runData = null;
          let pollTimedOut = false;
          for (let p = 0; p < 180; p++) {
            await sleep(1000);
            try {
              const pollRes = await fetch(`${API_BASE}/v1/test-runs/${runId}`, {
                headers: HEADERS,
                signal: AbortSignal.timeout(5000),
              });
              runData = await pollRes.json();
              if (terminal.has(runData.status)) break;
            } catch {}
          }
          if (!terminal.has(runData?.status)) {
            pollTimedOut = true;
            console.warn(`  -> Run ${runId} still ${runData?.status ?? 'unknown'} after 180s; cancelling`);
            await fetch(`${API_BASE}/v1/test-runs/${runId}/cancel`, {
              method: 'POST',
              headers: HEADERS,
              body: JSON.stringify({ reason: 'efficacy harness poll timeout' }),
              signal: AbortSignal.timeout(5000),
            }).catch(() => {});
            for (let p = 0; p < 20; p++) {
              await sleep(1000);
              try {
                const pollRes = await fetch(`${API_BASE}/v1/test-runs/${runId}`, {
                  headers: HEADERS,
                  signal: AbortSignal.timeout(5000),
                });
                runData = await pollRes.json();
                if (terminal.has(runData.status)) break;
              } catch {}
            }
          }

          let eventsData = null;
          try {
            const evRes = await fetch(`${API_BASE}/v1/test-runs/${runId}/events`, {
              headers: HEADERS,
              signal: AbortSignal.timeout(5000),
            });
            if (evRes.ok) {
              eventsData = await evRes.json();
            }
          } catch {}

          const safeMetadata = extractSafeProbeMetadata(runData?.probe_metadata, eventsData?.items ?? eventsData);
          const rawVerdict = runData?.verdict?.verdict ?? runData?.verdict?.conclusion ?? (pollTimedOut || runData?.status === 'failed' ? 'execution_error' : 'inconclusive');
          const isTerminalSuccess = !pollTimedOut && (runData?.status === 'verdicted' || runData?.status === 'completed');
          const outcome = pollTimedOut
            ? 'runner_timeout'
            : (isTerminalSuccess
              ? (runData?.outcome ?? runData?.verdict?.outcome ?? runData?.probe_external_result ?? safeMetadata?.external_result ?? 'completed')
              : (runData?.status === 'failed' ? (runData?.error ?? 'failed') : (runData?.status ?? 'timeout')));
          const grade = gradeResult(expectation.expected, rawVerdict, outcome, pollTimedOut ? 'runner_timeout' : runData?.status);
          const evidenceSummary = runData?.verdict?.explanation ?? runData?.verdict?.explanation_reason ?? runData?.summary?.text ?? (runData?.error ? `Error: ${runData.error}` : 'Probe observation recorded');

          console.log(`  -> Verdict: ${rawVerdict} | Grade: ${grade}`);

          const effectiveErrorClass = safeMetadata?.error_class ?? runData?.error_class;
          const row = {
            target: targetDecl.name,
            check_id: checkId,
            expected: expectation.expected,
            why: expectation.why ?? '',
            verdict: rawVerdict,
            outcome,
            status: runData?.status ?? 'unknown',
            grade,
            evidence_summary: evidenceSummary,
            run_id: runId,
            ...(safeMetadata ? { probe_metadata: safeMetadata } : {}),
            ...(runData?.error ? { error: runData.error } : {}),
            ...(effectiveErrorClass ? { error_class: effectiveErrorClass } : {}),
          };
          results.push(row);
          appendFileSync(jsonlPath, JSON.stringify(row) + '\n', 'utf8');

          const tallyKey = grade.replace(/\s+/g, '_');
          if (tally[tallyKey] !== undefined) {
            tally[tallyKey]++;
            categorizedChecks[tallyKey].push(checkId);
          }
        }
      }
    }

    const summaryPath = resolve(outDir, 'summary.md');
    const summaryMd = `# Efficacy Validation Summary: ${manifest.lab_id}

## Manifest Information
- **Lab ID**: \`${manifest.lab_id}\`
- **Manifest Path**: \`${manifestPath}\`
- **Total Checks Evaluated**: ${results.length}

## Confusion Matrix
| Category | Count | Evaluated Checks |
|---|---|---|
| **Detected Gap** | ${tally.detected_gap} | ${categorizedChecks.detected_gap.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **Missed Gap** | ${tally.missed_gap} | ${categorizedChecks.missed_gap.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **False Alarm** | ${tally.false_alarm} | ${categorizedChecks.false_alarm.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **Correct Protected** | ${tally.correct_protected} | ${categorizedChecks.correct_protected.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **Inconclusive** | ${tally.inconclusive} | ${categorizedChecks.inconclusive.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **Not Applicable** | ${tally.not_applicable} | ${categorizedChecks.not_applicable.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **Skipped Safety** | ${tally.skipped_safety} | ${categorizedChecks.skipped_safety.map((c) => `\`${c}\``).join(', ') || 'None'} |
| **Execution Error** | ${tally.execution_error} | ${categorizedChecks.execution_error.map((c) => `\`${c}\``).join(', ') || 'None'} |

## Detailed Results
| Target | Check ID | Expected | Verdict | Grade | Summary |
|---|---|---|---|---|---|
${results.map((r) => `| \`${r.target}\` | \`${r.check_id}\` | \`${r.expected}\` | \`${r.verdict}\` | **${r.grade}** | ${String(r.evidence_summary || '').replace(/\|/g, '\\|')} |`).join('\n')}
`;

    writeFileSync(summaryPath, summaryMd, 'utf8');
    console.log(`Wrote summary: ${summaryPath}`);

    console.log('\n--- CONFUSION MATRIX ---');
    console.table(tally);
  } finally {
    try {
      execFileSync('docker', ['rm', '-f', WORKER_NAME], { stdio: 'ignore' });
    } catch {}

    if (apiHandle?.started && apiHandle?.proc) {
      console.log('Stopping runner-spawned API process...');
      try {
        apiHandle.proc.kill('SIGKILL');
      } catch {}
    }
  }
}

const isDirectExecution = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isDirectExecution) {
  main().catch((err) => {
    console.error('Fatal runner error:', err);
    process.exit(1);
  });
}
