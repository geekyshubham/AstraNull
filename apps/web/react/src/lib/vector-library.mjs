const TARGET_KIND_ALIASES = Object.freeze({ domain: 'fqdn', hostname: 'fqdn' });
import { isDeclarationOnlyCheck } from './check-classification.mjs';

function text(value) {
  return String(value ?? '').trim();
}

function values(value) {
  return Array.isArray(value) ? value.map(text).filter(Boolean) : [];
}

export function effectiveVectorTargetKind(target) {
  const value = text(target?.value);
  if (/^https?:\/\//i.test(value)) return 'url';
  const kind = text(target?.kind).toLowerCase();
  return TARGET_KIND_ALIASES[kind] ?? kind;
}

export function vectorCheckSupportsTarget(check, target) {
  if (!check || !target) return false;
  const supported = values(check.supported_targets);
  return supported.length === 0 || supported.includes(effectiveVectorTargetKind(target));
}

export function evidenceCapabilityCopy(capability) {
  return {
    semantic_safe: {
      label: 'Semantic-safe evidence',
      detail: 'A bounded check can evaluate the stated behavior. Its run evidence still applies to the check, not automatically to every mapped vector.',
      tone: 'success',
    },
    declaration_only: {
      label: 'Declaration only',
      detail: 'E1 records customer-provided readiness metadata. It does not prove exposure or prevention.',
      tone: 'muted',
    },
    transport_only: {
      label: 'Transport only',
      detail: 'E2 can establish reachability or response behavior. It does not prove semantic susceptibility.',
      tone: 'muted',
    },
    soc_governed: {
      label: 'SOC-governed evidence',
      detail: 'Only an authorized governed workflow may establish this vector outcome. Customer-safe metadata is supplemental only.',
      tone: 'warn',
    },
    monitor_only: {
      label: 'Monitor only',
      detail: 'This vector needs passive telemetry or integration evidence; no active outside-in result is claimed.',
      tone: 'muted',
    },
  }[text(capability)] ?? {
    label: 'Evidence not classified',
    detail: 'No evidence capability is recorded for this vector.',
    tone: 'muted',
  };
}

export function vectorTargetAvailability(vector, checks, target) {
  const disposition = text(vector?.execution_disposition);
  if (disposition === 'soc_gated_only') {
    if (!target) {
      return {
        id: 'soc_gated',
        label: 'Request-only check',
        detail: 'Choose an exact declared domain or endpoint to start the mapped request-only check.',
        tone: 'muted',
        runnableChecks: [],
      };
    }
    const governedIds = new Set(values(vector?.soc_check_ids));
    const mappedGoverned = checks.filter((check) => (
      !isDeclarationOnlyCheck(check) && governedIds.has(text(check.check_id))
    ));
    const runnableGoverned = mappedGoverned.filter((check) => vectorCheckSupportsTarget(check, target));
    if (runnableGoverned.length > 0) {
      return {
        id: 'soc_gated',
        label: 'Request-only check available',
        detail: `${runnableGoverned.length} mapped request-only check${runnableGoverned.length === 1 ? '' : 's'} can be started on this target; the governed workflow records the verdict.`,
        tone: 'success',
        runnableChecks: runnableGoverned,
      };
    }
    return {
      id: 'soc_gated',
      label: 'Request-only check',
      detail: 'The mapped request-only check does not apply to this target kind.',
      tone: 'muted',
      runnableChecks: [],
    };
  }
  if (disposition === 'monitor_only') {
    return {
      id: 'monitor_only',
      label: 'Monitor only',
      detail: 'No active outside-in check is launched. Use integrated telemetry guidance.',
      tone: 'muted',
      runnableChecks: [],
    };
  }
  if (!target) {
    return {
      id: 'select_target',
      label: 'Select exact target',
      detail: 'Choose an exact declared domain or endpoint to evaluate compatible bounded checks.',
      tone: 'muted',
      runnableChecks: [],
    };
  }

  const safeIds = new Set(values(vector?.safe_check_ids));
  const mappedChecks = checks.filter((check) => !isDeclarationOnlyCheck(check) && safeIds.has(text(check.check_id)) && text(check.safety_class) === 'safe');
  const runnableChecks = mappedChecks.filter((check) => vectorCheckSupportsTarget(check, target));
  if (runnableChecks.length > 0) {
    return {
      id: 'safe_runnable',
      label: 'Bounded check available',
      detail: `${runnableChecks.length} mapped customer-safe check${runnableChecks.length === 1 ? '' : 's'} support this exact target.`,
      tone: 'success',
      runnableChecks,
    };
  }
  if (mappedChecks.length > 0) {
    return {
      id: 'target_not_supported',
      label: 'Target not supported',
      detail: `Mapped checks do not support target kind ${effectiveVectorTargetKind(target) || 'unknown'}.`,
      tone: 'muted',
      runnableChecks: [],
    };
  }
  return {
    id: 'additional_input',
    label: 'Additional input required',
    detail: 'A bounded mapping exists but needs customer-supplied setup such as an exact URL, route, or declaration before it is exposed as runnable.',
    tone: 'muted',
    runnableChecks: [],
  };
}

export function searchAndFilterVectors(vectors, options = {}) {
  const query = text(options.query).toLowerCase();
  const section = text(options.section);
  const capability = text(options.capability);
  const execution = text(options.execution);
  const targetAvailability = text(options.targetAvailability);
  const checks = Array.isArray(options.checks) ? options.checks : [];
  const target = options.target ?? null;
  return vectors.filter((vector) => {
    if (section && text(vector.section) !== section) return false;
    if (capability && text(vector.evidence_capability) !== capability) return false;
    if (execution && text(vector.execution_disposition) !== execution) return false;
    if (targetAvailability && vectorTargetAvailability(vector, checks, target).id !== targetAvailability) return false;
    if (!query) return true;
    return [
      vector.vector_id,
      vector.canonical_name,
      vector.section,
      vector.family,
      vector.protocol_service,
      vector.intended_detection_goal,
      vector.failure_means,
      vector.expected_controls,
    ].map(text).join(' ').toLowerCase().includes(query);
  });
}

const TARGET_FIT_ORDER = Object.freeze(['safe_runnable', 'additional_input', 'target_not_supported', 'monitor_only', 'soc_gated']);

export function sortVectorsByTargetFit(vectors, checks, target) {
  const rows = Array.isArray(vectors) ? [...vectors] : [];
  if (!target) return rows;
  const catalog = (Array.isArray(checks) ? checks : []).filter((check) => !isDeclarationOnlyCheck(check));
  const rank = (vector) => {
    const index = TARGET_FIT_ORDER.indexOf(vectorTargetAvailability(vector, catalog, target).id);
    return index < 0 ? TARGET_FIT_ORDER.length : index;
  };
  return rows
    .map((vector, index) => ({ vector, index, rank: rank(vector) }))
    .sort((left, right) => left.rank - right.rank || left.index - right.index)
    .map((entry) => entry.vector);
}

/**
 * Check-first hierarchy for the catalog: group each vector under the checks that cover it
 * (via safe_check_ids / mapped_check_ids), so the UI reads as checks with their vectors
 * nested rather than a flat vector dump. Vectors with no mapped catalog check fall into a
 * trailing `unmapped` bucket so nothing is hidden. Preserves the incoming vector order
 * within each group (callers sort vectors first).
 */
export function groupVectorsByCheck(vectors, checks) {
  const catalog = (Array.isArray(checks) ? checks : []).filter((check) => !isDeclarationOnlyCheck(check));
  const checkById = new Map(catalog.map((check) => [text(check?.check_id), check]));
  const groups = new Map();
  const unmapped = [];
  for (const vector of Array.isArray(vectors) ? vectors : []) {
    const ids = [...new Set([...values(vector?.safe_check_ids), ...values(vector?.mapped_check_ids)])]
      .filter((id) => checkById.has(id));
    if (ids.length === 0) {
      unmapped.push(vector);
      continue;
    }
    for (const id of ids) {
      let group = groups.get(id);
      if (!group) {
        group = { checkId: id, check: checkById.get(id), vectors: [] };
        groups.set(id, group);
      }
      group.vectors.push(vector);
    }
  }
  const ordered = [...groups.values()].sort((left, right) =>
    text(left.check?.canonical_name ?? left.check?.name ?? left.checkId)
      .localeCompare(text(right.check?.canonical_name ?? right.check?.name ?? right.checkId)));
  return { groups: ordered, unmapped };
}

export function countCompatibleSafeChecks(pairs, checks) {
  const catalog = new Map((Array.isArray(checks) ? checks : []).map((check) => [text(check?.check_id), check]));
  const safeIds = new Set();
  for (const pair of Array.isArray(pairs) ? pairs : []) {
    const checkId = text(pair?.check_id);
    if (!checkId) continue;
    if (isDeclarationOnlyCheck(pair?.catalog) || isDeclarationOnlyCheck(catalog.get(checkId))) continue;
    const safetyClass = text(pair?.catalog?.safety_class) || text(catalog.get(checkId)?.safety_class);
    if (safetyClass === 'safe') safeIds.add(checkId);
  }
  return safeIds.size;
}

export function latestRunForCheckOnTarget(runs, checkId, targetId) {
  const wantedCheck = text(checkId);
  const wantedTarget = text(targetId);
  if (!wantedCheck || !wantedTarget) return null;
  let latest = null;
  let latestAt = -Infinity;
  for (const run of Array.isArray(runs) ? runs : []) {
    if (text(run?.check_id) !== wantedCheck || text(run?.target_id) !== wantedTarget) continue;
    const at = Date.parse(text(run.started_at ?? run.created_at)) || 0;
    if (!latest || at > latestAt) {
      latest = run;
      latestAt = at;
    }
  }
  return latest;
}

export function preferredRunnableCheck(vector, availability) {
  const semanticIds = new Set(values(vector?.semantic_safe_check_ids));
  return availability?.runnableChecks?.find((check) => semanticIds.has(text(check.check_id))) ?? null;
}

export const CHECK_CATEGORIES = Object.freeze([
  Object.freeze({ id: 'waf', label: 'WAF', families: Object.freeze(['waf']) }),
  Object.freeze({ id: 'l7', label: 'Application (L7)', families: Object.freeze(['l7']) }),
  Object.freeze({ id: 'network', label: 'Network (L3/L4)', families: Object.freeze(['l3_l4']) }),
  Object.freeze({ id: 'dns', label: 'DNS', families: Object.freeze(['dns']) }),
  Object.freeze({ id: 'reflection', label: 'Reflection & amplification', families: Object.freeze(['reflection', 'amplification']) }),
  Object.freeze({ id: 'origin', label: 'Origin', families: Object.freeze(['origin', 'path']) }),
  Object.freeze({ id: 'protocol', label: 'TLS & protocol', families: Object.freeze(['tls', 'protocol']) }),
  Object.freeze({ id: 'operations', label: 'Operations', families: Object.freeze(['operations', 'high_scale']) }),
  Object.freeze({ id: 'exploit', label: 'Exploit & patterns', families: Object.freeze(['exploit', 'pattern']) }),
]);

export const MISC_CATEGORY_ID = 'misc';

export function checkCategoryId(check) {
  const family = text(check?.vector_family).toLowerCase();
  const category = CHECK_CATEGORIES.find((entry) => entry.families.includes(family));
  return category ? category.id : MISC_CATEGORY_ID;
}

export function categorizeCheckGroups(groups, unmapped, category = '') {
  const list = Array.isArray(groups) ? groups : [];
  const misc = Array.isArray(unmapped) ? unmapped : [];
  const counts = { all: list.length, [MISC_CATEGORY_ID]: misc.length };
  for (const entry of CHECK_CATEGORIES) counts[entry.id] = 0;
  const miscGroups = [];
  for (const group of list) {
    const id = checkCategoryId(group?.check);
    if (id === MISC_CATEGORY_ID) miscGroups.push(group);
    else counts[id] += 1;
  }
  counts[MISC_CATEGORY_ID] += miscGroups.length;
  const selected = text(category);
  const visibleGroups = !selected
    ? list
    : selected === MISC_CATEGORY_ID
      ? miscGroups
      : list.filter((group) => checkCategoryId(group?.check) === selected);
  const showMisc = !selected || selected === MISC_CATEGORY_ID;
  return { counts, groups: visibleGroups, unmapped: showMisc ? misc : [] };
}
