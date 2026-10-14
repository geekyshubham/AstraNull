/** View model for `GET /v1/test-runs/:id/verdict-replay`: stored verdict versus the same evidence under current rules. */
import { plainVerdictShortLabel } from './plain-language.mjs';
import { versionGapLabel } from './probe-evidence.mjs';

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export const REGRADED_LABEL = 'Re-graded with current signatures';

/** Why the stored responses could not be graded again; the verdict logic is still re-applied to the recorded outcome. */
export const REGRADE_UNAVAILABLE_COPY = Object.freeze({
  missing_response_features: 'This run did not store response details that can be graded again.',
  insufficient_feature_data: 'Some stored responses lack the status code needed to grade them again.',
  baseline_not_recorded: 'This run did not store the normal (baseline) response needed to grade the markers again.',
});

/** `{ regraded, label, note }` from a replay payload; null when the server did not say. */
export function regradeModel(payload) {
  const body = record(payload);
  const rederived = record(body?.rederived);
  const flag = typeof body?.regraded === 'boolean' ? body.regraded : typeof rederived?.regraded === 'boolean' ? rederived.regraded : null;
  if (flag === null) return null;
  if (flag) return { regraded: true, reason: '', label: REGRADED_LABEL, note: 'The stored responses were graded again with the current signatures and grading rules before the verdict logic ran.' };
  const reason = text(body?.regrade_unavailable_reason) || text(rederived?.regrade_unavailable_reason);
  const why = REGRADE_UNAVAILABLE_COPY[reason] ?? 'The stored responses could not be graded again.';
  return { regraded: false, reason, label: 'Verdict logic re-applied only', note: `${why} Only the verdict logic was re-applied to the recorded outcome, so signature changes are not reflected.` };
}

/** Plain outcome of a replay; `null` when the payload is unusable. */
export function verdictReplayModel(payload) {
  const body = record(payload);
  if (!body) return null;
  const stored = record(body.stored);
  const rederived = record(body.rederived) ?? {};
  const storedVerdict = text(stored?.verdict);
  const nowVerdict = text(rederived.verdict);
  const gapCode = text(body.grading_version_gap);
  const evidenceAvailable = rederived.evidence_available !== false;
  let state = 'unchanged';
  if (!evidenceAvailable) state = 'no_evidence';
  else if (!stored || !storedVerdict) state = 'no_stored';
  else if (body.changed === true || (nowVerdict && nowVerdict !== storedVerdict)) state = 'changed';
  const versions = (row) => [text(row?.grading_version), text(row?.signature_corpus_version)].filter(Boolean).join(' · ');
  return {
    state,
    storedVerdict,
    storedLabel: storedVerdict ? plainVerdictShortLabel(storedVerdict) : '',
    nowVerdict,
    nowLabel: nowVerdict ? plainVerdictShortLabel(nowVerdict) : '',
    explanation: text(rederived.explanation),
    declarationsApplied: rederived.declarations_applied === true,
    evidenceAvailable,
    versionGap: gapCode ? { code: gapCode, label: versionGapLabel(gapCode) || 'Grading rules changed — re-run to restore credit' } : null,
    storedVersions: versions(stored),
    currentVersions: versions(rederived),
    regrade: regradeModel(body),
  };
}

/** Plain message for a failed replay request; a missing replay is expected for old or foreign runs. */
export function verdictReplayErrorMessage(error) {
  const status = Number(record(error)?.status);
  if (status === 404) return 'No replay is available for this run. Runs recorded before replays existed, or without stored probe evidence, cannot be re-checked.';
  if (status === 403) return 'Your role cannot re-check verdicts for this run.';
  return 'The re-check could not run right now. The stored verdict is unchanged; try again shortly.';
}
