import { checkPresentation } from './check-presentation.mjs';
import { vectorCheckSupportsTarget } from './vector-library.mjs';
import { targetFixableReason } from './control-declarations.mjs';

export const OTHER_SECTION_ID = 'other';
export const OTHER_SECTION_LABEL = 'Other';
export const MONITOR_ONLY_TIER = 'E5';

function text(value) {
  return String(value ?? '').trim();
}

function humanize(value) {
  return text(value).replaceAll('_', ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

/** A port-less transport check is unsupported only until a target supplies the port, which the server answers per target. */
export function awaitsTargetPort(check) {
  const profile = check?.probe_profile && typeof check.probe_profile === 'object' ? check.probe_profile : {};
  return (Array.isArray(check?.runnable_requires) ? check.runnable_requires : []).includes('port')
    && ['tcp_connect', 'udp_probe'].includes(text(profile.kind))
    && profile.execution_supported !== false
    && !['default_port', 'service_port', 'port'].some((key) => Number.isInteger(profile[key]));
}

export function checkExclusionReason(check) {
  if (!check) return 'unknown_check';
  if (text(check.evidence_tier).toUpperCase() === MONITOR_ONLY_TIER) return 'monitor_only';
  if ((check.mechanism_supported === false || check.probe_profile?.delivery_supported === false
    || check.probe_profile?.execution_supported === false) && !awaitsTargetPort(check)) return 'unsupported_delivery';
  return null;
}

/** Adds checks a target-scoped catalog says this target can run, or can run once it declares something; the server decides, not the catalog flags. */
export function withTargetDependentChecks(checks, catalogs) {
  const base = Array.isArray(checks) ? checks : [];
  const known = new Set(base.map((check) => text(check?.check_id)));
  const extra = [];
  for (const catalog of Array.isArray(catalogs) ? catalogs : []) {
    for (const check of Array.isArray(catalog) ? catalog : []) {
      const id = text(check?.check_id);
      if (!id || known.has(id)) continue;
      if (check?.requires_additional_input !== false && !targetFixableReason(check?.additional_input_reason)) continue;
      known.add(id);
      extra.push(check);
    }
  }
  return extra.length ? [...base, ...extra] : base;
}

export function selectableChecks(checks) {
  const excluded = { soc_gated: 0, monitor_only: 0, not_customer_runnable: 0, unsupported_delivery: 0, total: 0 };
  const selectable = [];
  for (const check of Array.isArray(checks) ? checks : []) {
    const reason = checkExclusionReason(check);
    if (!reason) {
      selectable.push(check);
      continue;
    }
    excluded.total += 1;
    if (reason in excluded) excluded[reason] += 1;
  }
  return { checks: selectable, excluded };
}

function sectionOf(check) {
  const id = text(check?.section_id);
  const label = text(check?.section_label);
  if (id || label) return { id: id || label, label: label || id };
  const family = text(check?.vector_family);
  if (family) return { id: `family:${family}`, label: humanize(family) };
  return { id: OTHER_SECTION_ID, label: OTHER_SECTION_LABEL };
}

export function groupChecksBySection(checks) {
  const groups = new Map();
  for (const check of Array.isArray(checks) ? checks : []) {
    const section = sectionOf(check);
    if (!groups.has(section.id)) groups.set(section.id, { id: section.id, label: section.label, checks: [] });
    groups.get(section.id).checks.push(check);
  }
  return [...groups.values()].sort((left, right) => {
    if (left.id === OTHER_SECTION_ID) return 1;
    if (right.id === OTHER_SECTION_ID) return -1;
    return left.label.localeCompare(right.label);
  });
}

export function checkSupportsTarget(check, target) {
  return vectorCheckSupportsTarget(check, target);
}

export function checkTargetCoverage(check, targets) {
  const list = Array.isArray(targets) ? targets : [];
  const supportedTargetIds = list.filter((target) => checkSupportsTarget(check, target)).map((target) => text(target.id));
  return { supported: supportedTargetIds.length, total: list.length, supportedTargetIds };
}

export function checkProbeSummary(check) {
  const profile = check?.probe_profile && typeof check.probe_profile === 'object' ? check.probe_profile : {};
  const maxRequests = Number(profile.max_requests);
  const timeoutMs = Number(profile.timeout_ms);
  return {
    kind: text(profile.kind) || null,
    maxRequests: Number.isFinite(maxRequests) && maxRequests >= 0 ? maxRequests : null,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : null,
  };
}

export function filterChecks(checks, query) {
  const needle = text(query).toLowerCase();
  const list = Array.isArray(checks) ? checks : [];
  if (!needle) return list;
  return list.filter((check) => [
    check.check_id,
    check.name,
    check.description,
    checkPresentation(check).name,
    checkPresentation(check).purpose,
    check.vector_family,
    check.section_label,
    check.evidence_tier,
    check.probe_profile?.kind,
  ].map(text).join(' ').toLowerCase().includes(needle));
}

export function summarizeSelection({ checks, selectedIds, targets, targetId = null }) {
  const selected = new Set((Array.isArray(selectedIds) ? selectedIds : []).map(text).filter(Boolean));
  const scopedTargets = (Array.isArray(targets) ? targets : []).filter((target) => !targetId || text(target.id) === text(targetId));
  const selectedChecks = (Array.isArray(checks) ? checks : []).filter((check) => selected.has(text(check.check_id)));
  let stepCount = 0;
  let requestUpperBound = 0;
  let requestBoundKnown = true;
  const incompatible = [];
  const applicableTargetIds = new Set();
  for (const check of selectedChecks) {
    const coverage = checkTargetCoverage(check, scopedTargets);
    coverage.supportedTargetIds.forEach((id) => applicableTargetIds.add(id));
    if (coverage.supported === 0) {
      incompatible.push({
        check_id: text(check.check_id),
        name: checkPresentation(check).name,
        supported_targets: Array.isArray(check.supported_targets) ? check.supported_targets.map(text) : [],
      });
      continue;
    }
    stepCount += coverage.supported;
    const probe = checkProbeSummary(check);
    if (probe.maxRequests === null) requestBoundKnown = false;
    else requestUpperBound += probe.maxRequests * coverage.supported;
  }
  return {
    selectedCount: selectedChecks.length,
    stepCount,
    requestUpperBound: requestBoundKnown ? requestUpperBound : null,
    incompatible,
    applicableTargetCount: applicableTargetIds.size,
    targetCount: scopedTargets.length,
  };
}
