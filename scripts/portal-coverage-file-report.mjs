#!/usr/bin/env node
import fs from 'node:fs';

const usage = 'Usage: node scripts/portal-coverage-file-report.mjs <full-reconciliation-report.json> [--file <substring>] [--limit <rows>]';

export function summarizePortalCoverageByFile(report) {
  const portal = report.portal ?? {};
  const rows = new Map();
  const row = (action) => {
    const file = String(action).split('#')[0];
    if (!rows.has(file)) rows.set(file, { file, covered: 0, uncovered: 0, unclassified: 0, notApplicable: 0 });
    return rows.get(file);
  };
  for (const cell of portal.covered ?? []) row(cell.action).covered += 1;
  for (const cell of portal.uncovered ?? []) row(cell.action).uncovered += 1;
  for (const cell of portal.unclassifiedStates ?? []) row(cell.action).unclassified += 1;
  for (const cell of portal.notApplicable ?? []) row(cell.action).notApplicable += 1;
  return [...rows.values()].filter((entry) => !entry.file.startsWith('route:') && !entry.file.startsWith('dataset:'))
    .sort((a, b) => (b.uncovered + b.unclassified) - (a.uncovered + a.unclassified));
}

export function main(args = process.argv.slice(2)) {
  const [reportPath, ...rest] = args;
  if (!reportPath || reportPath === '--help') { process.stdout.write(`${usage}\n`); return reportPath ? 0 : 1; }
  const options = { file: '', limit: 40 };
  for (let index = 0; index < rest.length; index += 2) {
    if (rest[index] === '--file') options.file = rest[index + 1] ?? '';
    else if (rest[index] === '--limit') options.limit = Number(rest[index + 1]);
    else throw new Error(`Unknown argument: ${rest[index]}`);
  }
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  const rows = summarizePortalCoverageByFile(report).filter((entry) => entry.file.includes(options.file));
  const totals = rows.reduce((sum, entry) => ({ covered: sum.covered + entry.covered, uncovered: sum.uncovered + entry.uncovered, unclassified: sum.unclassified + entry.unclassified, notApplicable: sum.notApplicable + entry.notApplicable }), { covered: 0, uncovered: 0, unclassified: 0, notApplicable: 0 });
  for (const entry of rows.slice(0, options.limit)) process.stdout.write(`${String(entry.covered).padStart(7)} covered ${String(entry.uncovered).padStart(7)} uncovered ${String(entry.unclassified).padStart(7)} unclassified ${String(entry.notApplicable).padStart(7)} n/a  ${entry.file}\n`);
  process.stdout.write(`${JSON.stringify({ files: rows.length, ...totals })}\n`);
  return 0;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(new URL(import.meta.url).pathname)) process.exitCode = main();
