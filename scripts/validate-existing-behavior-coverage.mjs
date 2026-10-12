#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EXISTING_BEHAVIOR_ROOT, existingBehaviorSourceFiles, captureExistingBehaviorInvocation, readExistingBehaviorInvocation } from '../tests/helpers/existing-behavior-coverage.mjs';

const usage = `Usage:
  node scripts/validate-existing-behavior-coverage.mjs --capture node --out /tmp/receipt-prefix -- node --test --test-reporter=tap tests/unit/owned.test.mjs
  node scripts/validate-existing-behavior-coverage.mjs --capture playwright --out /tmp/receipt-prefix -- node_modules/.bin/playwright test tests/e2e/journeys/owned.spec.mjs --workers=1 --retries=0 --reporter=json
  node scripts/validate-existing-behavior-coverage.mjs --invocation /tmp/receipt-prefix.invocation.json [--invocation ...] --report /tmp/full-report.json
  Add --focused for explicitly partial reporting: it never claims full acceptance; invalid evidence still fails.
Full reconciliation exits nonzero for any applicable coverage gaps, missing inventories or invalid/stale evidence.
No test filename, registration, or invented pass result is execution evidence.`;

export function existingBehaviorCoverageExitCode(report, focused = false) {
  const invalid = report.errors.length || report.delivery.errors?.length || report.portal.rejected?.length
    || report.portal.publicAuth?.rejected?.length;
  return focused ? invalid ? 1 : 0 : report.complete ? 0 : 1;
}

export async function main(args = process.argv.slice(2)) {
  const options = { invocations: [], focused: false };
  const seenOptions = new Set();
  let command = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--') { command = args.slice(index + 1); break; }
    if (arg !== '--invocation') {
      if (seenOptions.has(arg)) throw new Error(`Duplicate option: ${arg}`);
      seenOptions.add(arg);
    }
    if (arg === '--help') { process.stdout.write(usage + '\n'); return 0; }
    if (arg === '--focused') { options.focused = true; continue; }
    if (['--capture', '--out', '--report', '--invocation'].includes(arg)) {
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error(`Missing value for ${arg}`);
      if (arg === '--invocation') options.invocations.push(path.resolve(value));
      else options[arg.slice(2)] = value;
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  const root = EXISTING_BEHAVIOR_ROOT;
  const files = existingBehaviorSourceFiles(root);
  if (options.capture) {
    if (!options.out || !command.length || options.invocations.length || options.report || options.focused) throw new Error('Capture needs --out and an actual command after --; reconciliation is a separate operation.');
    const prefix = path.resolve(options.out);
    const invocationPath = prefix + '.invocation.json';
    const captured = await captureExistingBehaviorInvocation({ root, files, runner: options.capture, command,
      logPath: prefix + '.log', reportPath: options.capture === 'playwright' ? prefix + '.playwright.json' : undefined, invocationPath });
    const checked = readExistingBehaviorInvocation(captured, { root, files: existingBehaviorSourceFiles(root) });
    process.stdout.write(JSON.stringify({ mode: 'capture', invocation: invocationPath, exitCode: captured.exitCode,
      sourceDigest: captured.sourceBinding.digest, assertions: checked.results.reduce((count, result) => count + result.receipts.length, 0), errors: checked.errors }) + '\n');
    return checked.errors.length ? 1 : 0;
  }
  if (command.length || options.out) throw new Error('Commands/--out are only valid with --capture.');
  const { buildExistingBehaviorCoverage, accountExistingBehaviorCoverage } = await import('../tests/fixtures/existing-behavior-coverage.mjs');
  const manifest = buildExistingBehaviorCoverage({ root, files });
  const invocations = options.invocations.map((file) => readExistingBehaviorInvocation(file, { root, files }));
  const report = accountExistingBehaviorCoverage(manifest, invocations);
  report.mode = options.focused ? 'focused-partial' : 'full-reconciliation';
  report.acceptance = options.focused ? 'not-a-full-acceptance-report' : report.complete ? 'complete' : 'incomplete';
  if (options.focused) report.complete = false;
  if (options.report) {
    fs.mkdirSync(path.dirname(path.resolve(options.report)), { recursive: true });
    fs.writeFileSync(options.report, JSON.stringify(report, null, 2) + '\n');
  }
  process.stdout.write(JSON.stringify({ mode: report.mode, acceptance: report.acceptance, complete: report.complete,
    sourceDigest: report.sourceDigest, invocationCount: report.invocationCount, errors: report.errors,
    delivery: { complete: report.delivery.complete, invoked: report.delivery.invoked_definitions ?? 0, gaps: report.delivery.gaps?.length, errors: report.delivery.errors },
    portal: { complete: report.portal.complete, covered: report.portal.covered?.length, gaps: report.portal.uncovered?.length,
      unresolved: report.portal.unresolvedSourceRoots?.length, unmapped: report.portal.unmappedSourceActions?.length, rejected: report.portal.rejected?.length,
      publicAuth: report.portal.publicAuth ? { complete: report.portal.publicAuth.complete, covered: report.portal.publicAuth.covered?.length,
        gaps: report.portal.publicAuth.uncovered?.length, unclassified: report.portal.publicAuth.unclassifiedStates?.length,
        unresolved: report.portal.publicAuth.unresolvedSourceRoots?.length, unmapped: report.portal.publicAuth.unmappedSourceActions?.length,
        rejected: report.portal.publicAuth.rejected?.length } : null },
    report: options.report ? path.resolve(options.report) : null }) + '\n');
  return existingBehaviorCoverageExitCode(report, options.focused);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await main(); }
  catch (error) { process.stderr.write(`${error.stack ?? error}\n`); process.exitCode = 1; }
}
