const TARGET_KIND_ALIASES = Object.freeze({ domain: 'fqdn', hostname: 'fqdn' });

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
      tone: 'info',
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
    return {
      id: 'soc_gated',
      label: 'Governed scenario',
      detail: 'This scenario is governed and not customer-runnable directly.',
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
      detail: 'Choose a declared target group and exact target to evaluate compatible bounded checks.',
      tone: 'info',
      runnableChecks: [],
    };
  }

  const safeIds = new Set(values(vector?.safe_check_ids));
  const mappedChecks = checks.filter((check) => safeIds.has(text(check.check_id)) && text(check.safety_class) === 'safe');
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
    tone: 'info',
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

export function preferredRunnableCheck(vector, availability) {
  const semanticIds = new Set(values(vector?.semantic_safe_check_ids));
  return availability?.runnableChecks?.find((check) => semanticIds.has(text(check.check_id))) ?? null;
}
