import { VECTOR_LIBRARY, VECTOR_LIBRARY_TOTAL } from '../contracts/vectorLibrary.mjs';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const MAX_SEARCH_LENGTH = 200;
const FILTER_FIELDS = Object.freeze([
  'vector_id',
  'section',
  'domain',
  'scope',
  'family',
  'validation_tier',
  'evidence_tier',
  'evidence_capability',
  'execution_disposition',
  'registry_source',
]);
const SEARCH_FIELDS = Object.freeze([
  'vector_id',
  'section',
  'domain',
  'scope',
  'family',
  'canonical_name',
  'protocol_service',
  'delivery_mechanism',
  'how_it_works',
  'targeted_resource_or_assumption',
  'defensive_indicators',
  'primary_controls',
  'boundaries',
  'validation_tier',
  'registry_source',
  'registry_id',
  'registry_name',
  'registry_domain',
  'exhausted_resource',
  'coverage_status',
  'out_of_scope_reason',
  'evidence_tier',
  'evidence_capability',
  'execution_disposition',
  'intended_detection_goal',
  'failure_means',
  'expected_controls',
]);

function boundedInteger(value, fallback, min, max) {
  if (value == null || value === '') return fallback;
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function normalizedFilter(value) {
  return String(value ?? '').trim().toLocaleLowerCase('en-US');
}

export function listVectors(options = {}) {
  const limit = boundedInteger(options.limit, DEFAULT_LIMIT, 1, MAX_LIMIT);
  const offset = boundedInteger(options.offset, 0, 0, VECTOR_LIBRARY_TOTAL);
  const search = normalizedFilter(options.search ?? options.q).slice(0, MAX_SEARCH_LENGTH);
  const checkId = String(options.check_id ?? '').trim();

  let filtered = VECTOR_LIBRARY;
  if (search) {
    filtered = filtered.filter((row) => SEARCH_FIELDS.some((field) => (
      normalizedFilter(row[field]).includes(search)
    )));
  }
  for (const field of FILTER_FIELDS) {
    const expected = normalizedFilter(options[field]);
    if (!expected) continue;
    filtered = filtered.filter((row) => normalizedFilter(row[field]) === expected);
  }
  if (checkId) filtered = filtered.filter((row) => row.check_ids.includes(checkId));

  const items = filtered.slice(offset, offset + limit);
  return {
    items,
    count: items.length,
    meta: {
      total: VECTOR_LIBRARY_TOTAL,
      filtered_total: filtered.length,
      offset,
      limit,
      returned: items.length,
    },
  };
}
