import '../helpers/dev-data-dir.mjs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  bindExistingBehaviorSources, existingBehaviorSourceFiles, recordExistingBehaviorReceipt, captureExistingBehaviorInvocation,
  readExistingBehaviorInvocation, adaptNodeTapResults, adaptPlaywrightJsonResults,
  reconcileExistingBehaviorCoverage,
} from '../helpers/existing-behavior-coverage.mjs';

const helperPath = fileURLToPath(new URL('../helpers/existing-behavior-coverage.mjs', import.meta.url));
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'astranull-existing-behavior-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, 'src/production.mjs'), 'export const bound = 1;\n');
  await writeFile(path.join(root, 'adapter.mjs'), await readFile(helperPath));
  return root;
}
function report(results, errors = []) {
  return { errors, suites: [{ title: 'file', specs: [{ title: 'actual case', id: 'pw_test_1', tests: [{ expectedStatus: 'passed', status: 'expected', results }] }] }] };
}
const assertion = (extra = {}) => ({ schema: 'existing-behavior-assertion/v1', invocationId: 'inv_1', sourceDigest: 'a'.repeat(64), testId: 'pw_test_1', retry: 0, channel: 'portal', observations: ['exact target remained selected'], receipt: { cellId: 'cell_1' }, completedAt: '2026-10-12T00:00:00.000Z', ...extra });
const attachment = (receipt) => ({ name: 'existing-behavior-receipt-1', contentType: 'application/json', body: Buffer.from(JSON.stringify(receipt)).toString('base64') });

test('source binding hashes ordered relevant files and changes for production, test, fixture and config changes', async (t) => {
  const root = await fixture(t);
  for (const name of ['test.mjs', 'fixture.mjs', 'vite.config.ts']) await writeFile(path.join(root, name), '// initial\n');
  const files = ['src/production.mjs', 'test.mjs', 'fixture.mjs', 'vite.config.ts', 'adapter.mjs'];
  const binding = bindExistingBehaviorSources({ root, files });
  assert.equal(binding.digest, bindExistingBehaviorSources({ root, files: files.slice().reverse() }).digest);
  await writeFile(path.join(root, 'output.log'), 'transient log ignored\n');
  assert.equal(binding.digest, bindExistingBehaviorSources({ root, files }).digest);
  for (const name of files) {
    const before = bindExistingBehaviorSources({ root, files }).digest;
    await writeFile(path.join(root, name), '// changed\n');
    assert.notEqual(before, bindExistingBehaviorSources({ root, files }).digest, name);
  }
  assert.throws(() => bindExistingBehaviorSources({ root, files: ['../foreign.mjs'] }), /outside|relative/);
  assert.throws(() => bindExistingBehaviorSources({ root, files: ['missing.mjs'] }), /ENOENT|missing/);
});

test('default invocation read discovers new relevant source files rather than trusting the captured file list', async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, 'tests'));
  await writeFile(path.join(root, 'src/adapter.mjs'), await readFile(helperPath));
  await writeFile(path.join(root, 'tests/case.test.mjs'), `import {it} from 'node:test';import {assertExistingBehaviorCase} from '../src/adapter.mjs';it('actual pass',async(t)=>{await assertExistingBehaviorCase(t,{channel:'delivery',receipt:{check_id:'check_1'}},async()=>['actual assertion completed']);});\n`);
  const captured = await captureExistingBehaviorInvocation({ root, runner: 'node', command: [process.execPath, '--test', '--test-reporter=tap', 'tests/case.test.mjs'], logPath: path.join(root, 'node.tap') });
  assert.equal(captured.exitCode, 0);
  assert.equal(readExistingBehaviorInvocation(captured, { root }).errors.length, 0);
  await writeFile(path.join(root, 'src/new-production-dependency.mjs'), 'export const added = true;\n');
  const changed = readExistingBehaviorInvocation(captured, { root });
  assert.equal(changed.results[0].status, 'passed', 'retained terminal pass is unchanged');
  assert.ok(changed.errors.includes('stale-source'));
  assert.equal(reconcileExistingBehaviorCoverage({ sourceBinding: captured.sourceBinding }, [changed]).accepted.delivery.length, 0);
  const explicitFixtureFiles = captured.sourceBinding.files.map((item) => item.path);
  assert.equal(readExistingBehaviorInvocation(captured, { root, files: explicitFixtureFiles }).errors.length, 0, 'explicit focused fixture file lists remain supported');
});

test('source discovery includes root and frontend TypeScript, Playwright and Vite configurations', async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, 'apps/web/react'), { recursive: true });
  const configs = ['tsconfig.json', 'tsconfig.app.json', 'playwright.config.mjs', 'playwright.integration.config.ts', 'vite.config.ts',
    'apps/web/react/tsconfig.json', 'apps/web/react/tsconfig.node.json', 'apps/web/react/playwright.config.ts', 'apps/web/react/vite.config.mts'];
  for (const file of configs) await writeFile(path.join(root, file), '// source config fixture\n');
  const files = existingBehaviorSourceFiles(root);
  for (const config of configs) assert.ok(files.includes(config), `missing configuration: ${config}`);
  const actualRoot = path.resolve(path.dirname(helperPath), '../..');
  const actualFiles = existingBehaviorSourceFiles(actualRoot);
  for (const config of ['tsconfig.json', 'playwright.config.mjs', 'vite.config.ts']) assert.ok(actualFiles.includes(config), `missing actual repository configuration: ${config}`);
  const before = bindExistingBehaviorSources({ root }).digest;
  await writeFile(path.join(root, 'apps/web/react/tsconfig.node.json'), '// changed frontend dependency\n');
  assert.notEqual(before, bindExistingBehaviorSources({ root }).digest);
});

test('standalone receipt emission has no coverage and bound emission requires concrete observations', async () => {
  const env = { ...process.env };
  delete process.env.EXISTING_BEHAVIOR_INVOCATION_ID; delete process.env.EXISTING_BEHAVIOR_SOURCE_DIGEST;
  try {
    assert.equal(await recordExistingBehaviorReceipt({}, { channel: 'portal', receipt: {} }, ['a checked fact']), null);
    process.env.EXISTING_BEHAVIOR_INVOCATION_ID = 'inv_1'; process.env.EXISTING_BEHAVIOR_SOURCE_DIGEST = 'a'.repeat(64);
    await assert.rejects(recordExistingBehaviorReceipt({ testId: 't', attach() {} }, { channel: 'portal', receipt: {} }, []), /observations|assertions/);
  } finally {
    for (const key of ['EXISTING_BEHAVIOR_INVOCATION_ID', 'EXISTING_BEHAVIOR_SOURCE_DIGEST']) {
      if (env[key] === undefined) delete process.env[key]; else process.env[key] = env[key];
    }
  }
});

test('actual Node TAP invocation pairs assertion events with terminal pass and retained source-bound logs', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'case.test.mjs'), `import {describe,it} from 'node:test';\nimport assert from 'node:assert/strict';\nimport {assertExistingBehaviorCase} from './adapter.mjs';\ndescribe('parent',()=>it('exact child',async(t)=>{await assertExistingBehaviorCase(t,{channel:'delivery',receipt:{check_id:'check_1'}},async()=>{assert.equal(2+2,4);return ['actual callback assertion completed'];});}));\n`);
  const files = ['src/production.mjs', 'adapter.mjs', 'case.test.mjs'];
  const captured = await captureExistingBehaviorInvocation({ root, runner: 'node', command: [process.execPath, '--test', '--test-reporter=tap', 'case.test.mjs'], files, logPath: path.join(root, 'node.tap'), invocationPath: path.join(root, 'invocation.json') });
  assert.equal(captured.exitCode, 0);
  const adapted = readExistingBehaviorInvocation(captured, { root, files });
  assert.equal(adapted.errors.length, 0);
  assert.equal(adapted.results.length, 1);
  assert.equal(adapted.results[0].testId, 'parent > exact child');
  assert.equal(adapted.results[0].receipts[0].channel, 'delivery');
  const aggregate = reconcileExistingBehaviorCoverage({ sourceBinding: captured.sourceBinding }, [adapted]);
  assert.equal(aggregate.accepted.delivery.length, 1);
  assert.equal(aggregate.complete, false, 'missing inventories cannot be accepted as full coverage');
  await writeFile(path.join(root, 'src/production.mjs'), 'export const bound = 2;\n');
  assert.ok(readExistingBehaviorInvocation(captured, { root, files }).errors.includes('stale-source'));
});

test('failed, skipped and TODO Node tests do not establish pass receipts; incomplete TAP is not accepted', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'case.test.mjs'), `import {it} from 'node:test';\nimport {recordExistingBehaviorReceipt} from './adapter.mjs';\nit('then fails',async(t)=>{await recordExistingBehaviorReceipt(t,{channel:'delivery',receipt:{check_id:'check_1'}},['early assertion']);throw new Error('later assertion failed');});\nit('skipped',{skip:true},()=>{});\nit('todo',{todo:true},()=>{});\n`);
  const files = ['src/production.mjs', 'adapter.mjs', 'case.test.mjs'];
  const captured = await captureExistingBehaviorInvocation({ root, runner: 'node', command: [process.execPath, '--test', '--test-reporter=tap', 'case.test.mjs'], files, logPath: path.join(root, 'node.tap') });
  assert.notEqual(captured.exitCode, 0);
  const read = readExistingBehaviorInvocation(captured, { root, files });
  assert.ok(read.errors.includes('invocation-not-passed'));
  assert.equal(reconcileExistingBehaviorCoverage({ sourceBinding: captured.sourceBinding }, [read]).accepted.delivery.length, 0);
  assert.ok(adaptNodeTapResults('TAP version 13\n# Subtest: incomplete\nok 1 - incomplete\n').errors.includes('missing-tap-summary'));
});

test('Playwright adapter requires actual passed result, zero retries, bound inline assertion attachments and no global errors', () => {
  const result = { status: 'passed', retry: 0, errors: [], attachments: [attachment(assertion())] };
  const adapted = adaptPlaywrightJsonResults(report([result]));
  assert.equal(adapted.results[0].testId, 'pw_test_1');
  assert.equal(adapted.results[0].receipts.length, 1);
  for (const variant of [{ ...result, status: 'failed' }, { ...result, status: 'skipped' }, { ...result, retry: 1 }, { ...result, errors: [{ message: 'late failure' }] }]) {
    assert.notEqual(adaptPlaywrightJsonResults(report([variant])).results[0].status, 'passed');
  }
  assert.notEqual(adaptPlaywrightJsonResults(report([result, result])).results[0].status, 'passed');
  assert.ok(adaptPlaywrightJsonResults(report([result], [{ message: 'beforeAll failed' }])).errors.includes('playwright-global-errors'));
  assert.equal(adaptPlaywrightJsonResults(report([{ ...result, attachments: [{ name: 'portal-action-receipt-static', body: attachment(assertion()).body }] }])).results[0].receipts.length, 0);
});

test('an unreceipted skipped, interrupted or retried Playwright case makes the whole invocation unusable', () => {
  const passed = { status: 'passed', retry: 0, errors: [], attachments: [attachment(assertion())] };
  for (const result of [
    { status: 'skipped', retry: 0 },
    { status: 'interrupted', retry: 0 },
    { status: 'failed', retry: 0 },
    { status: 'timedOut', retry: 0 },
    { status: 'passed', retry: 1 },
  ]) {
    const mixed = report([passed]);
    mixed.suites[0].specs.push({ id: 'pw_unreceipted', tests: [{ expectedStatus: 'passed', status: 'expected', results: [{ ...result, attachments: [] }] }] });
    const adapted = adaptPlaywrightJsonResults(mixed);
    assert.equal(adapted.results[0].status, 'passed', 'the first concrete assertion still passed');
    assert.equal(adapted.results[1].receipts.length, 0, 'absence of receipts must not hide a nonpassing terminal case');
    assert.ok(adapted.errors.includes('playwright-not-all-passed'));
    const sourceBinding = { digest: assertion().sourceDigest };
    const invocation = { invocationId: 'inv_1', sourceBinding, exitCode: 0, ...adapted };
    assert.equal(reconcileExistingBehaviorCoverage({ sourceBinding }, [invocation]).accepted.portal.length, 0);
  }
});

test('retained log tampering cannot turn a failure or names-only inventory into covered behavior', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'case.test.mjs'), `import {it} from 'node:test';it('registered test name',()=>{});\n`);
  const files = ['adapter.mjs', 'case.test.mjs', 'src/production.mjs'];
  const captured = await captureExistingBehaviorInvocation({ root, runner: 'node', command: [process.execPath, '--test', '--test-reporter=tap', 'case.test.mjs'], files, logPath: path.join(root, 'node.tap') });
  assert.equal(captured.exitCode, 0);
  assert.equal(readExistingBehaviorInvocation(captured, { root, files }).results.filter((result) => result.receipts.length).length, 0);
  await writeFile(captured.log.path, 'TAP version 13\n# pass 999\n# fail 0\n');
  assert.ok(readExistingBehaviorInvocation(captured, { root, files }).errors.includes('log-digest-mismatch'));
});

test('central reconciliation rejects mismatched identity, invocation, source and empty observation claims', async (t) => {
  const root = await fixture(t);
  const sourceBinding = bindExistingBehaviorSources({ root, files: ['adapter.mjs', 'src/production.mjs'] });
  const portal = { sourceDigest: 'portal-current', inventory: { unresolved: [] }, unmappedSourceActions: [], cells: [{ id: 'cell_1', applicable: true }] };
  const delivery = { rows: [{ check_id: 'check_1', check_version: 'v1', delivery_fingerprint: 'fp', disposition: 'declaration_only' }] };
  const manifest = { sourceBinding, portal, delivery };
  // Adapter-shaped objects are test fixtures only; production CLI always reparses hash-checked retained logs.
  const receipt = assertion({ sourceDigest: sourceBinding.digest, receipt: { schema: 'portal-action-execution/v1', testId: 'pw_test_1', cellId: 'cell_1', sourceDigest: 'portal-current', observations: ['checked action'] } });
  const invocation = { invocationId: 'inv_1', sourceBinding, exitCode: 0, errors: [], startedAt: '2026-10-11T23:59:59.000Z', finishedAt: '2026-10-12T00:00:01.000Z', results: [{ testId: 'pw_test_1', status: 'passed', retry: 0, receipts: [receipt] }] };
  const reconcilePortal = (_coverage, results) => ({ complete: results.some((result) => result.receipts.length), covered: results.flatMap((result) => result.receipts), uncovered: [], rejected: [] });
  const accountDelivery = (receipts) => ({ complete: false, gaps: ['check_1'], receipts });
  assert.equal(reconcileExistingBehaviorCoverage(manifest, [invocation], { reconcilePortal, accountDelivery }).accepted.portal.length, 1);
  for (const update of [{ testId: 'different' }, { invocationId: 'foreign' }, { sourceDigest: 'b'.repeat(64) }, { observations: [] }, { retry: 1 },
    { completedAt: '' }, { completedAt: 'not-a-date' }, { completedAt: '2026-10-12' },
    { completedAt: '2026-10-11T23:59:58.999Z' }, { completedAt: '2026-10-12T00:00:01.001Z' }]) {
    const altered = { ...invocation, results: [{ ...invocation.results[0], receipts: [{ ...receipt, ...update }] }] };
    assert.equal(reconcileExistingBehaviorCoverage(manifest, [altered], { reconcilePortal, accountDelivery }).accepted.portal.length, 0);
  }
  for (const changed of [{ startedAt: 'invalid' }, { finishedAt: '2026-10-11T23:59:58.000Z' }]) {
    assert.equal(reconcileExistingBehaviorCoverage(manifest, [{ ...invocation, ...changed }], { reconcilePortal, accountDelivery }).accepted.portal.length, 0);
  }
  assert.equal(reconcileExistingBehaviorCoverage(manifest, [], { reconcilePortal, accountDelivery }).complete, false);
});

test('retained actual pass rejects mutated invocation windows, runner flags and receipt completion times', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'case.test.mjs'), `import {it} from 'node:test';import {assertExistingBehaviorCase} from './adapter.mjs';it('actual pass',async(t)=>{await assertExistingBehaviorCase(t,{channel:'delivery',receipt:{check_id:'check_1'}},async()=>['actual assertion completed']);});\n`);
  const files = ['adapter.mjs', 'case.test.mjs', 'src/production.mjs'];
  const captured = await captureExistingBehaviorInvocation({ root, runner: 'node', command: [process.execPath, '--test', '--test-reporter=tap', 'case.test.mjs'], files, logPath: path.join(root, 'node.tap') });
  assert.equal(captured.exitCode, 0);
  assert.equal(readExistingBehaviorInvocation(captured, { root, files }).errors.length, 0);
  for (const changed of [{ startedAt: 'not-a-date' }, { finishedAt: '2020-01-01T00:00:00.000Z' }]) {
    assert.ok(readExistingBehaviorInvocation({ ...captured, ...changed }, { root, files }).errors.includes('invalid-invocation'));
  }
  for (const flag of ['--test-only', '--test-rerun-failures=/tmp/previous', '--test-reporter=spec']) {
    assert.ok(readExistingBehaviorInvocation({ ...captured, command: [...captured.command, flag] }, { root, files }).errors.includes('invalid-invocation-command'));
  }
  const original = await readFile(captured.log.path, 'utf8');
  const { createHash } = await import('node:crypto');
  for (const completedAt of ['nonsense', '2020-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z']) {
    const altered = original.replace(/"completedAt":"[^"]+"/, `"completedAt":"${completedAt}"`);
    await writeFile(captured.log.path, altered);
    const withCorrectLogDigest = { ...captured, log: { ...captured.log, sha256: createHash('sha256').update(altered).digest('hex') } };
    const read = readExistingBehaviorInvocation(withCorrectLogDigest, { root, files });
    assert.equal(read.results[0].status, 'passed', 'terminal test still passed');
    assert.ok(read.errors.includes('invalid-assertion-timestamp'));
  }
  for (const command of [['pw', 'test', '--retries=0', '--retries=2', '--reporter=json'], ['pw', 'test', '--retries=0', '--reporter=json', '--reporter=line']]) {
    await assert.rejects(captureExistingBehaviorInvocation({ root, runner: 'playwright', command, logPath: path.join(root, 'pw.log'), reportPath: path.join(root, 'pw.json') }), /Playwright coverage/);
    assert.ok(readExistingBehaviorInvocation({ ...captured, runner: 'playwright', command, report: { path: path.join(root, 'absent.json'), sha256: 'a'.repeat(64) } }, { root, files }).errors.includes('invalid-invocation-command'));
  }
});

test('focused CLI reporting rejects nested public-auth invalid proofs without treating missing coverage as an invalid receipt', async () => {
  const { existingBehaviorCoverageExitCode } = await import('../../scripts/validate-existing-behavior-coverage.mjs');
  const partial = { complete: false, errors: [], delivery: { errors: [] }, portal: { rejected: [], publicAuth: { rejected: [], uncovered: [{ id: 'missing-public' }] } } };
  assert.equal(existingBehaviorCoverageExitCode(partial, true), 0);
  assert.equal(existingBehaviorCoverageExitCode(partial, false), 1);
  const invalid = { ...partial, portal: { ...partial.portal, publicAuth: { ...partial.portal.publicAuth, rejected: [{ reason: 'invalid-public-action-proof' }] } } };
  assert.equal(existingBehaviorCoverageExitCode(invalid, true), 1);
  assert.equal(existingBehaviorCoverageExitCode(invalid, false), 1);
});

test('CLI rejects duplicate singleton options rather than replacing their values', async () => {
  const { main } = await import('../../scripts/validate-existing-behavior-coverage.mjs');
  for (const args of [['--capture', 'node', '--capture', 'playwright'], ['--out', '/tmp/one', '--out', '/tmp/two'], ['--report', '/tmp/one', '--report', '/tmp/two'], ['--focused', '--focused']]) {
    await assert.rejects(main(args), /Duplicate option/);
  }
});
