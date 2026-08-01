/**
 * Vector-heatmap coverage derivation.
 *
 * Plain `.mjs` (with a sibling `.d.mts` so the `.tsx` can import it under `allowJs: false`)
 * because `node --test` cannot load TypeScript. The alternative — and what
 * `tests/unit/react-portal-no-fabricated-runtime.test.mjs` used to do — is to re-implement
 * these helpers in the test file. That copy had already drifted: it resolved ids from
 * `check_id`/`checkId` only and omitted the nested `check.check_id` and `target_group.id`
 * fallbacks that actually ship, so every nested record shape was handled in production and
 * exercised nowhere.
 *
 * The heatmap's whole claim is that a cell reflects real records and never fabricates
 * coverage, so this derivation is the part that most needs to be testable directly.
 */

/** Vector families and the substrings that assign a check to each. */
export const VECTOR_FAMILIES = [
  { label: 'Origin', keys: ['origin'] },
  { label: 'L3/L4', keys: ['l3_l4', 'l3/l4', 'layer_3_4'] },
  { label: 'DNS', keys: ['dns'] },
  { label: 'L7/API', keys: ['l7_api', 'l7/api', 'application', 'api'] },
  { label: 'Protocol', keys: ['protocol', 'tls', 'http2', 'http3'] },
];

/**
 * Lowercased string for family matching. Absent values become '' so they cannot match.
 *
 * @param {Record<string, unknown>} item
 * @param {string} key
 */
export function stringValue(item, key) {
  const value = item[key];
  return value === undefined || value === null ? '' : String(value).toLowerCase();
}

/**
 * One level into a nested object, e.g. `{ check: { check_id } }`.
 *
 * Arrays are rejected because an array index is not a field name. Note this is belt-and-braces
 * for the current callers: neither `id` nor `check_id` exists on an array, so those lookups
 * already yield ''. It only bites for a nested key an array does own (`length`), so do not read
 * the guard as the thing keeping array shapes out of the counts — `itemCheckId` /
 * `itemTargetGroupId` returning '' is. Case is preserved — unlike `stringValue`, this feeds
 * identity comparisons, not substring matching.
 *
 * @param {Record<string, unknown>} item
 * @param {string} key
 * @param {string} nestedKey
 */
export function nestedString(item, key, nestedKey) {
  const value = item[key];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return '';
  const nested = /** @type {Record<string, unknown>} */ (value)[nestedKey];
  return nested === undefined || nested === null ? '' : String(nested);
}

/**
 * A record's check id, accepting snake_case, camelCase, or a nested `check` object.
 *
 * API payloads and hydrated portal rows disagree on shape, and a record whose id fails to
 * resolve silently drops out of every count — which reads as "no coverage" rather than as a
 * shape mismatch. Hence the fallbacks.
 *
 * @param {Record<string, unknown>} item
 */
export function itemCheckId(item) {
  return String(item.check_id ?? item.checkId ?? nestedString(item, 'check', 'check_id') ?? '');
}

/**
 * A record's target-group id, accepting snake_case, camelCase, or a nested `target_group`.
 *
 * @param {Record<string, unknown>} item
 */
export function itemTargetGroupId(item) {
  return String(
    item.target_group_id ?? item.targetGroupId ?? nestedString(item, 'target_group', 'id') ?? '',
  );
}

/**
 * Whether a check belongs to a vector family.
 *
 * Matches against family, category, name and id together so a check is still classified when
 * only its name or id carries the vector, which is common for catalog entries that predate
 * `vector_family`.
 *
 * @param {Record<string, unknown>} check
 * @param {{ keys: string[] }} family
 */
export function checkMatchesFamily(check, family) {
  const haystack = [
    stringValue(check, 'vector_family'),
    stringValue(check, 'category'),
    stringValue(check, 'name'),
    stringValue(check, 'check_id'),
  ].join(' ');
  return family.keys.some((key) => haystack.includes(key));
}

/**
 * The check ids belonging to one family.
 *
 * @param {Record<string, unknown>[]} checks
 * @param {{ keys: string[] }} family
 * @returns {Set<string>}
 */
export function familyCheckIds(checks, family) {
  return new Set(
    checks
      .filter((check) => checkMatchesFamily(check, family))
      .map((check) => String(check.check_id ?? check.id ?? ''))
      .filter(Boolean),
  );
}

/**
 * @typedef {'evidence' | 'run' | 'policy' | 'none' | 'no-data'} FamilyCoverageStatus
 * @typedef {{ status: FamilyCoverageStatus, policyCount: number, runCount: number,
 *   evidenceCount: number }} FamilyCoverage
 */

/**
 * Coverage for one family/group cell, counted from real records only.
 *
 * `no-data` and `none` are deliberately distinct: `no-data` means the question does not apply
 * (no declared group, or no checks in this family), while `none` means it applies and nothing
 * was found. Collapsing them would report an unasked question as a failing one.
 *
 * Status is the strongest evidence present — evidence beats a run, a run beats a policy —
 * because a policy that has produced evidence is more than merely declared.
 *
 * @param {{ checkIds: Set<string>, groupId: string,
 *   testPolicies: Record<string, unknown>[], runs: Record<string, unknown>[],
 *   evidence: Record<string, unknown>[] }} input
 * @returns {FamilyCoverage}
 */
export function familyCoverage({ checkIds, groupId, testPolicies, runs, evidence }) {
  if (!groupId || checkIds.size === 0) {
    return { status: 'no-data', policyCount: 0, runCount: 0, evidenceCount: 0 };
  }
  const inCell = (item) => itemTargetGroupId(item) === groupId && checkIds.has(itemCheckId(item));
  const policyCount = testPolicies.filter(inCell).length;
  const runCount = runs.filter(inCell).length;
  const evidenceCount = evidence.filter(inCell).length;
  /** @type {FamilyCoverageStatus} */
  let status = 'none';
  if (evidenceCount > 0) status = 'evidence';
  else if (runCount > 0) status = 'run';
  else if (policyCount > 0) status = 'policy';
  return { status, policyCount, runCount, evidenceCount };
}
