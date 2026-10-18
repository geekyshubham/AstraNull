import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const EXISTING_BEHAVIOR_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const ASSERTION_SCHEMA = 'existing-behavior-assertion/v1';
const sha = (value) => createHash('sha256').update(value).digest('hex');
const observationsValid = (value) => Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === 'string' && item.trim());
const sourceExtensions = /\.(?:mjs|cjs|js|jsx|ts|tsx|mts|cts|css|json|sql|html|ya?ml|sh|bash|py|conf|cfg|nft|rules)$/;
const sourceBasenames = /^(?:Dockerfile(?:\.[\w-]+)?|Containerfile|Makefile|\.dockerignore)$/;
const ignored = new Set(['node_modules', '.git', '.vite', 'dist', 'build', 'coverage', 'test-results', 'playwright-report', 'output']);

/** Relevant production, fixture, assertion and startup dependencies; generated portal bundles and logs are not sources. */
export function existingBehaviorSourceFiles(root = EXISTING_BEHAVIOR_ROOT) {
  const files = [];
  const walk = (relative) => {
    const absolute = path.join(root, relative);
    if (!fs.existsSync(absolute)) return;
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`Source symlink is not allowed: ${relative}`);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(absolute).sort()) if (!ignored.has(entry)) walk(path.join(relative, entry));
    } else if (sourceExtensions.test(relative) || sourceBasenames.test(path.basename(relative))) files.push(relative.split(path.sep).join('/'));
  };
  for (const directory of ['src', 'workers', 'apps/web/react/src', 'tests', 'db', 'scripts', 'ops']) walk(directory);
  for (const file of ['package.json', 'package-lock.json', 'apps/web/react/index.html']) walk(file);
  const configName = /^(?:tsconfig(?:\.[^.]+)*\.json|(?:playwright|vite)(?:\.[^.]+)*\.config\.[cm]?[jt]s)$/;
  for (const directory of ['', 'apps/web/react']) {
    const absolute = path.join(root, directory);
    if (fs.existsSync(absolute)) for (const name of fs.readdirSync(absolute).sort()) {
      if (configName.test(name)) walk(path.join(directory, name));
    }
  }
  return [...new Set(files)].sort();
}

export function bindExistingBehaviorSources({ root = EXISTING_BEHAVIOR_ROOT, files = existingBehaviorSourceFiles(root) } = {}) {
  const base = fs.realpathSync(root);
  const manifest = [...new Set(files)].sort().map((relative) => {
    if (typeof relative !== 'string' || path.isAbsolute(relative) || relative.split(/[\\/]/).some((part) => part === '..' || !part)) throw new Error('Sources must be safe root-relative paths, never outside the source root.');
    const absolute = path.resolve(base, relative);
    if (!fs.realpathSync(absolute).startsWith(base + path.sep)) throw new Error(`Source outside root: ${relative}`);
    let cursor = base;
    for (const part of relative.split('/')) { cursor = path.join(cursor, part); if (fs.lstatSync(cursor).isSymbolicLink()) throw new Error(`Source symlink is not allowed: ${relative}`); }
    if (!fs.statSync(absolute).isFile()) throw new Error(`Source is not a file: ${relative}`);
    return { path: relative, sha256: sha(fs.readFileSync(absolute)) };
  });
  if (!manifest.length) throw new Error('Source binding requires relevant source files.');
  return { schema: 'existing-behavior-source/v1', files: manifest, digest: sha(JSON.stringify(manifest)) };
}

/** Called only after the caller's behavior assertions complete; terminal result is still required. */
export async function recordExistingBehaviorReceipt(testContext, { channel, receipt }, observations) {
  const invocationId = process.env.EXISTING_BEHAVIOR_INVOCATION_ID;
  const sourceDigest = process.env.EXISTING_BEHAVIOR_SOURCE_DIGEST;
  if (!invocationId || !sourceDigest) return null;
  if (!/^[a-f0-9]{64}$/.test(sourceDigest)) throw new Error('Invalid invocation source digest.');
  if (!['portal', 'delivery'].includes(channel) || !receipt || typeof receipt !== 'object') throw new Error('An actual channel receipt is required.');
  if (!observationsValid(observations)) throw new Error('Concrete completed behavior assertions/observations are required.');
  const testId = testContext.testId || testContext.fullName;
  if (!testId) throw new Error('Actual test context identity is required.');
  const envelope = { schema: ASSERTION_SCHEMA, invocationId, sourceDigest, testId, retry: testContext.retry ?? 0,
    channel, receipt, observations, completedAt: new Date().toISOString(),
    ...(process.env.EXISTING_BEHAVIOR_RUNTIME_DIGEST ? { runtimeDigest: process.env.EXISTING_BEHAVIOR_RUNTIME_DIGEST,
      runtimeObserved: { platform: process.platform, arch: process.arch, node: process.version } } : {}) };
  if (typeof testContext.attach === 'function') {
    await testContext.attach(`existing-behavior-receipt-${sha(JSON.stringify(envelope)).slice(0, 16)}`, { body: JSON.stringify(envelope), contentType: 'application/json' });
  } else if (typeof testContext.diagnostic === 'function') testContext.diagnostic(JSON.stringify(envelope));
  else throw new Error('An actual Node or Playwright test context is required.');
  return envelope;
}

export async function assertExistingBehaviorCase(testContext, descriptor, assertBehavior) {
  if (typeof assertBehavior !== 'function') throw new Error('Behavior assertions callback is required.');
  const observations = await assertBehavior();
  if (!observationsValid(observations)) throw new Error('Concrete completed behavior assertions/observations are required.');
  return recordExistingBehaviorReceipt(testContext, descriptor, observations);
}

// Native TAP adds one transport-escaping layer around diagnostics and test names.
// Decode only that layer, never JSON escapes or a permissive parse fallback.
function decodeNodeTapText(value) {
  return value.replace(/\\([\s\S])|\\$/g, (match, escaped) => {
    if (escaped !== '\\' && escaped !== '#') throw new Error('Invalid native TAP escape.');
    return escaped;
  });
}

/** Node diagnostics follow their containing terminal test at the same indentation. Never infer proof from a test title. */
export function adaptNodeTapResults(tap) {
  const errors = [];
  const identityText = (value) => {
    try { return decodeNodeTapText(value); }
    catch { errors.push('malformed-tap-identity'); return value; }
  };
  const results = [];
  const headings = new Map();
  const terminals = new Map();
  for (const line of tap.split(/\r?\n/)) {
    const heading = line.match(/^(\s*)# Subtest: (.*)$/);
    if (heading) {
      const indent = heading[1].length;
      for (const key of headings.keys()) if (key >= indent) headings.delete(key);
      headings.set(indent, identityText(heading[2]));
      continue;
    }
    const terminal = line.match(/^(\s*)(not ok|ok) \d+ - (.*)$/);
    if (terminal) {
      const indent = terminal[1].length;
      const name = identityText(terminal[3].replace(/\s+# (?:SKIP|TODO).*$/i, ''));
      const testId = [...headings].filter(([level]) => level < indent).sort((a, b) => a[0] - b[0]).map(([, title]) => title).concat(name).join(' > ');
      const result = { testId, status: terminal[2] === 'ok' && !/\s+# (?:SKIP|TODO)/i.test(terminal[3]) ? 'passed' : 'not-passed', retry: 0, receipts: [] };
      terminals.set(indent, result);
      results.push(result);
      continue;
    }
    const diagnostic = line.match(/^(\s*)# (\{.*)$/);
    if (diagnostic) {
      try {
        const receipt = JSON.parse(decodeNodeTapText(diagnostic[2]));
        if (receipt.schema !== ASSERTION_SCHEMA) continue;
        const containing = terminals.get(diagnostic[1].length);
        if (!containing || containing.testId !== receipt.testId) errors.push('tap-receipt-test-mismatch');
        else containing.receipts.push(receipt);
      } catch { if (diagnostic[2].includes(ASSERTION_SCHEMA)) errors.push('malformed-tap-receipt'); }
    }
  }
  const counts = Object.fromEntries([...tap.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)].map((match) => [match[1], Number(match[2])]));
  if (!/^TAP version 13\r?$/m.test(tap) || !/^1\.\.\d+\r?$/m.test(tap) || ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'].some((key) => counts[key] === undefined)) errors.push('missing-tap-summary');
  if (counts.fail || counts.cancelled || counts.skipped || counts.todo || counts.tests === 0) errors.push('tap-not-all-passed');
  return { errors, results: results.filter((result) => result.receipts.length), terminalTests: counts };
}

/** Actual Playwright JSON spec.id matches testInfo.testId; only single terminal expected passes count. */
export function adaptPlaywrightJsonResults(report) {
  const errors = [];
  const results = [];
  if (!report || !Array.isArray(report.suites)) return { errors: ['missing-playwright-report'], results };
  if (report.errors?.length) errors.push('playwright-global-errors');
  const visit = (suite) => {
    for (const spec of suite.specs ?? []) for (const test of spec.tests ?? []) {
      const history = test.results ?? [];
      const terminal = history.at(-1);
      const passed = !!spec.id && test.expectedStatus === 'passed' && test.status === 'expected' && history.length === 1
        && terminal?.status === 'passed' && terminal.retry === 0 && !terminal.error && !terminal.errors?.length;
      if (!passed) errors.push('playwright-not-all-passed');
      const receipts = [];
      for (const item of terminal?.attachments ?? []) {
        if (!item.name?.startsWith('existing-behavior-receipt-')) continue;
        if (item.contentType !== 'application/json' || !item.body) { errors.push('missing-inline-playwright-receipt'); continue; }
        try { receipts.push(JSON.parse(Buffer.from(item.body, 'base64').toString('utf8'))); }
        catch { errors.push('malformed-playwright-receipt'); }
      }
      results.push({ testId: spec.id, status: passed ? 'passed' : 'not-passed', retry: terminal?.retry ?? -1, receipts });
    }
    for (const child of suite.suites ?? []) visit(child);
  };
  for (const suite of report.suites) visit(suite);
  if (!results.length) errors.push('missing-playwright-tests');
  return { errors, results };
}

function validateInvocationCommand(runner, command, reportPath) {
  if (!Array.isArray(command) || !command.length || command.some((item) => typeof item !== 'string')) throw new Error('Actual command is required.');
  if (runner === 'node') {
    if (!command.includes('--test') || !command.includes('--test-reporter=tap')
      || command.filter((arg) => arg.startsWith('--test-reporter')).length !== 1
      || command.some((arg) => /--test-(?:only|rerun-failures)/.test(arg))) throw new Error('Node coverage requires --test --test-reporter=tap without selective rerun.');
  } else if (runner === 'playwright') {
    if (!command.includes('--retries=0') || !command.includes('--reporter=json') || !reportPath
      || command.filter((arg) => arg.startsWith('--retries')).length !== 1
      || command.filter((arg) => arg.startsWith('--reporter')).length !== 1) throw new Error('Playwright coverage requires --retries=0 --reporter=json and a retained report path.');
  } else throw new Error('Runner must be node or playwright.');
}

/** Captures a real process, not supplied pass objects. Report/log bytes are retained and hashed. */
export async function captureExistingBehaviorInvocation({ root = EXISTING_BEHAVIOR_ROOT, runner, command, files, logPath, reportPath, invocationPath, env = {} }) {
  if (!logPath) throw new Error('Retained log path is required.');
  validateInvocationCommand(runner, command, reportPath);
  const sourceBinding = bindExistingBehaviorSources({ root, files });
  const invocationId = randomUUID();
  const startedAt = new Date().toISOString();
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  if (reportPath) { fs.mkdirSync(path.dirname(reportPath), { recursive: true }); fs.rmSync(reportPath, { force: true }); }
  const log = fs.createWriteStream(logPath);
  let launchError = null;
  const runtimeProvenance = { schema: 'existing-behavior-runtime/v1', platform: process.platform, arch: process.arch, node: process.version, scope: 'local-process', executable: command[0] };
  const childEnv = { ...process.env, ...env, EXISTING_BEHAVIOR_INVOCATION_ID: invocationId,
    EXISTING_BEHAVIOR_SOURCE_DIGEST: sourceBinding.digest, EXISTING_BEHAVIOR_RUNTIME_DIGEST: sha(JSON.stringify(runtimeProvenance)),
    ...(runner === 'playwright' ? { PLAYWRIGHT_JSON_OUTPUT_FILE: reportPath } : {}) };
  // A capture invoked inside node:test must launch a new runner, not inherit its worker protocol.
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawn(command[0], command.slice(1), { cwd: root, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (data) => log.write(data)); child.stderr.on('data', (data) => log.write(data));
  child.on('error', (error) => { launchError = error.message; log.write(error.stack ?? error.message); });
  const { exitCode, signal } = await new Promise((resolve) => child.on('close', (exitCode, signal) => resolve({ exitCode, signal })));
  await new Promise((resolve, reject) => { log.on('error', reject); log.end(resolve); });
  const retained = (file) => ({ path: path.resolve(file), sha256: sha(fs.readFileSync(file)) });
  const invocation = { schema: 'existing-behavior-invocation/v1', invocationId, runner, command, startedAt, finishedAt: new Date().toISOString(),
    exitCode, signal, launchError, sourceBinding,
    runtimeProvenance,
    log: retained(logPath), report: reportPath && fs.existsSync(reportPath) ? retained(reportPath) : null };
  if (invocationPath) { fs.mkdirSync(path.dirname(invocationPath), { recursive: true }); fs.writeFileSync(invocationPath, JSON.stringify(invocation, null, 2) + '\n'); }
  return invocation;
}

export function readExistingBehaviorInvocation(input, { root = EXISTING_BEHAVIOR_ROOT, files } = {}) {
  const invocation = typeof input === 'string' ? JSON.parse(fs.readFileSync(input, 'utf8')) : input;
  const errors = [];
  if (invocation.schema !== 'existing-behavior-invocation/v1' || !invocation.invocationId || !validInvocationWindow(invocation)) errors.push('invalid-invocation');
  const runtime = invocation.runtimeProvenance;
  if (runtime?.schema !== 'existing-behavior-runtime/v1' || !runtime.platform || !runtime.arch || !/^v\d+\.\d+\.\d+/.test(runtime.node ?? '')
    || runtime.scope !== 'local-process' || runtime.executable !== invocation.command?.[0]) errors.push('invalid-runtime-provenance');
  try { validateInvocationCommand(invocation.runner, invocation.command, invocation.report?.path); } catch { errors.push('invalid-invocation-command'); }
  if (invocation.exitCode !== 0 || invocation.signal || invocation.launchError) errors.push('invocation-not-passed');
  try {
    const current = bindExistingBehaviorSources({ root, files: files ?? existingBehaviorSourceFiles(root) });
    if (current.digest !== invocation.sourceBinding?.digest || JSON.stringify(current.files) !== JSON.stringify(invocation.sourceBinding?.files)) errors.push('stale-source');
  } catch { errors.push('missing-source'); }
  const bytes = (record, kind) => {
    if (!record?.path || !record.sha256) { errors.push(`missing-${kind}`); return null; }
    try { const value = fs.readFileSync(record.path); if (sha(value) !== record.sha256) { errors.push(`${kind}-digest-mismatch`); return null; } return value.toString('utf8'); }
    catch { errors.push(`missing-${kind}`); return null; }
  };
  const log = bytes(invocation.log, 'log');
  let adapted = { errors: [], results: [] };
  if (invocation.runner === 'node' && log !== null) adapted = adaptNodeTapResults(log);
  else if (invocation.runner === 'playwright') {
    const report = bytes(invocation.report, 'report');
    if (report !== null) { try { adapted = adaptPlaywrightJsonResults(JSON.parse(report)); } catch { errors.push('malformed-playwright-report'); } }
  } else errors.push('invalid-runner-or-log');
  for (const result of adapted.results) for (const envelope of result.receipts) {
    if (!assertionInWindow(envelope, invocation)) errors.push('invalid-assertion-timestamp');
    if (envelope.runtimeDigest !== sha(JSON.stringify(invocation.runtimeProvenance ?? null))
      || ['platform', 'arch', 'node'].some((key) => envelope.runtimeObserved?.[key] !== invocation.runtimeProvenance?.[key])
      || (envelope.channel === 'delivery' && envelope.receipt?.runtime_provenance && ['platform', 'node'].some((key) => envelope.receipt.runtime_provenance[key] !== envelope.runtimeObserved?.[key]))) errors.push('assertion-runtime-mismatch');
  }
  return { ...invocation, results: adapted.results, errors: [...errors, ...adapted.errors] };
}

function canonicalTimestamp(value) {
  if (typeof value !== 'string') return null;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? time : null;
}
function validInvocationWindow(invocation) {
  const start = canonicalTimestamp(invocation.startedAt);
  const end = canonicalTimestamp(invocation.finishedAt);
  return start !== null && end !== null && start <= end;
}
function assertionInWindow(envelope, invocation) {
  const time = canonicalTimestamp(envelope.completedAt);
  return validInvocationWindow(invocation) && time !== null
    && time >= canonicalTimestamp(invocation.startedAt) && time <= canonicalTimestamp(invocation.finishedAt);
}

export function reconcileExistingBehaviorCoverage(manifest, invocations, { reconcilePortal, accountDelivery, scope = 'full-product' } = {}) {
  if (!['full-product', 'delivery-only'].includes(scope)) throw new Error(`Unknown reconciliation scope: ${scope}`);
  const accepted = { portal: [], delivery: [] };
  const portalResults = [];
  const errors = [];
  const seenInvocations = new Set();
  for (const invocation of invocations) {
    if (seenInvocations.has(invocation.invocationId)) { errors.push('duplicate-invocation'); continue; }
    seenInvocations.add(invocation.invocationId);
    if (invocation.errors?.length || invocation.exitCode !== 0 || invocation.sourceBinding?.digest !== manifest.sourceBinding?.digest) {
      errors.push(...(invocation.errors ?? []), 'unusable-invocation'); continue;
    }
    for (const result of invocation.results ?? []) for (const envelope of result.receipts ?? []) {
      const valid = result.status === 'passed' && result.retry === 0 && envelope.schema === ASSERTION_SCHEMA && envelope.retry === 0
        && envelope.testId === result.testId && envelope.invocationId === invocation.invocationId
        && envelope.sourceDigest === manifest.sourceBinding.digest && observationsValid(envelope.observations)
        && (!invocation.runtimeProvenance || (envelope.runtimeDigest === sha(JSON.stringify(invocation.runtimeProvenance))
          && ['platform', 'arch', 'node'].every((key) => envelope.runtimeObserved?.[key] === invocation.runtimeProvenance[key])))
        && (envelope.channel !== 'delivery' || !envelope.receipt?.runtime_provenance || ['platform', 'node'].every((key) => envelope.receipt.runtime_provenance[key] === envelope.runtimeObserved?.[key]))
        && assertionInWindow(envelope, invocation) && !!envelope.receipt && ['portal', 'delivery'].includes(envelope.channel);
      if (!valid) { errors.push('invalid-assertion-receipt'); continue; }
      accepted[envelope.channel].push(envelope.receipt);
      if (envelope.channel === 'portal') portalResults.push({ testId: result.testId, status: result.status, retry: result.retry, receipts: [envelope.receipt] });
    }
  }
  const portal = scope === 'delivery-only' ? { required: false, complete: null, reason: 'outside-delivery-only-scope' }
    : manifest.portal && reconcilePortal ? reconcilePortal(manifest.portal, portalResults) : { complete: false, reason: 'missing-portal-inventory-or-adapter' };
  const delivery = manifest.delivery && accountDelivery ? accountDelivery(accepted.delivery, manifest.delivery) : { complete: false, reason: 'missing-delivery-inventory-or-adapter' };
  return { schema: 'existing-behavior-report/v1', scope, complete: !errors.length && (scope === 'delivery-only' || portal.complete) && delivery.complete,
    sourceDigest: manifest.sourceBinding?.digest, invocationCount: invocations.length, accepted, errors, portal, delivery };
}
