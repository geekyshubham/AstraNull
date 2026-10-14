import { additionalInputReasonCopy, controlsHref } from './control-declarations.mjs';

/** Server explanation reason for a finished run that sent nothing because a check input was missing. */
export const REQUIRED_INPUT_MISSING = 'required_input_missing';
export const NOT_TESTED_LABEL = 'Not tested';
export const NOT_TESTED_DETAIL = 'No requests were sent, so this is not a failed check. Add what is missing, then run it again.';

const REASON_ALIASES = Object.freeze({
  missing_declared_origin_binding: 'origin_binding_required',
  missing_target_bound_direct_address: 'target_bound_direct_address_required',
});

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function flagged(...rows) {
  return rows.some((row) => row && [row.explanation_reason, row.inconclusive_reason].some((value) => text(value) === REQUIRED_INPUT_MISSING));
}

function inputCode(...rows) {
  for (const row of rows) {
    if (!row) continue;
    for (const value of [record(row.summary)?.required_input_missing, row.required_input, row.missing_input]) {
      const code = text(value);
      if (code && code !== REQUIRED_INPUT_MISSING) return REASON_ALIASES[code] ?? code;
    }
  }
  return '';
}

function needsPhrase(label) {
  const rest = text(label).replace(/^Needs\s+/, '');
  return rest && rest !== text(label) ? rest : '';
}

/** Plain fallback when the server sent no message: "Not tested — this check needs <input> on the target, so nothing was sent." */
export function notTestedSentence(code) {
  const copy = additionalInputReasonCopy(code);
  const phrase = needsPhrase(copy?.label);
  if (!phrase) return 'Not tested — this check needs more input, so nothing was sent.';
  return `Not tested — this check needs ${phrase}${copy.section ? ' on the target' : ''}, so nothing was sent.`;
}

/**
 * Reads a run, scan step, verdict or evidence answer and returns plain copy when it finished as
 * `required_input_missing`; null otherwise. The server's own message wins over the fallback.
 */
export function requiredInputMissing(source) {
  const row = record(source);
  if (!row) return null;
  const verdict = record(row.verdict);
  const placement = record(verdict?.placement_confidence) ?? record(row.placement_confidence);
  const summary = record(row.summary);
  const placementFlag = placement && [placement.explanation_reason, placement.reason].some((value) => text(value) === REQUIRED_INPUT_MISSING);
  if (!flagged(row, verdict) && !placementFlag && !text(summary?.required_input_missing)) return null;
  const reason = inputCode(row, verdict);
  const copy = additionalInputReasonCopy(reason);
  const serverMessage = text(verdict?.explanation) || text(row.explanation);
  return {
    reason,
    label: NOT_TESTED_LABEL,
    message: serverMessage || notTestedSentence(reason),
    serverMessage: Boolean(serverMessage),
    section: copy?.section ?? '',
    cta: copy?.cta ?? '',
    tone: 'muted',
  };
}

/** Controls link for the missing input, or '' when no target setting can supply it. */
export function requiredInputMissingHref(info, targetId) {
  const section = text(info?.section);
  const id = text(targetId);
  return section && id ? controlsHref(id, section) : '';
}
