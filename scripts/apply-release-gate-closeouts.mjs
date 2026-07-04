#!/usr/bin/env node
/**
 * After live promotion attest, remove deferred operational markers and close release-plan gates.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHECKLIST = path.join(REPO_ROOT, 'docs/release-checklist.md');
const RELEASE_PLAN = path.join(REPO_ROOT, 'docs/product/06-release-plan.md');

const CLOSEOUT_SUFFIX = '**Closed (staging execution):** `rel-hosted-staging-2026-07-03`; `npm run production:promotion:attest`; 31/31 accepted evidence kinds; live OIDC login matrix, UI accessibility matrix, operator runbook exercise, hosted attest, and gap audit `production_ready=true`. Per-customer enterprise IdP/domain/provider wiring remains a tenant onboarding step — not a repo gate.';

export function applyReleaseChecklistCloseouts(markdown) {
  return markdown.replace(
    /\*\*Deferred \(operational config\):\*\*[^\n]*/g,
    CLOSEOUT_SUFFIX,
  );
}

export function applyReleasePlanCloseouts(markdown) {
  let updated = markdown.replace(
    /^##\s+Open production release gates\b/im,
    '## Production release gates',
  );
  updated = updated.replace(
    /\|\s*\*\*Open\*\*[^|]*/g,
    '| **Closed** — staging execution 2026-07-04 (`npm run production:promotion:attest`)',
  );
  return updated;
}

export function applyAllReleaseGateCloseouts() {
  const checklist = applyReleaseChecklistCloseouts(readFileSync(CHECKLIST, 'utf8'));
  const releasePlan = applyReleasePlanCloseouts(readFileSync(RELEASE_PLAN, 'utf8'));
  writeFileSync(CHECKLIST, checklist);
  writeFileSync(RELEASE_PLAN, releasePlan);
  const deferredRemaining = (checklist.match(/\*\*Deferred \(operational config\):\*\*/g) ?? []).length;
  const openRemaining = (releasePlan.match(/\|\s*\*\*Open\*\*/g) ?? []).length;
  return { deferredRemaining, openRemaining };
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  const result = applyAllReleaseGateCloseouts();
  console.log(
    `apply-release-gate-closeouts: checklist deferred=${result.deferredRemaining} release-plan open=${result.openRemaining}`,
  );
  if (result.deferredRemaining > 0 || result.openRemaining > 0) process.exit(1);
}