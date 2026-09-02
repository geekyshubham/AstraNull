/** Return the effective target kind used by check compatibility gates. */
export function effectiveTargetKind(target) {
  if (/^https?:\/\//i.test(String(target?.value ?? ''))) return 'url';
  return target?.kind ?? null;
}

/**
 * Return the stable API error for a check/target mismatch, or null when compatible.
 * This is metadata-only and performs no target lookup or network activity.
 */
export function targetKindCompatibilityError(check, target) {
  const targetKind = effectiveTargetKind(target);
  if (
    !Array.isArray(check?.supported_targets)
    || check.supported_targets.length === 0
    || check.supported_targets.includes(targetKind)
  ) {
    return null;
  }
  return {
    error: 'target_kind_not_supported',
    status: 400,
    check_id: check.check_id,
    target_kind: targetKind,
    supported_targets: [...check.supported_targets],
  };
}
