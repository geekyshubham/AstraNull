function asItem(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function textOf(item, key) {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

function runRef(row) {
  const testRunId = textOf(row, 'test_run_id');
  if (!testRunId) return null;
  return {
    testRunId,
    status: textOf(row, 'status'),
    createdAt: textOf(row, 'created_at'),
    finalized: typeof row?.finalized === 'boolean' ? row.finalized : null,
    reason: textOf(row, 'reason'),
  };
}

/**
 * Finding lineage exactly as `GET /v1/findings/:id` presents it. Only rows with explicit retest
 * intent are retests; a later run of the same target and check without that intent stays a later
 * run and never advances remediation. Sibling closure is never implied.
 */
export function readFindingLineage(finding) {
  const lineage = asItem(finding?.lineage);
  const originating = asItem(lineage?.originating) ?? asItem(finding?.originating);
  const latest = asItem(lineage?.latest) ?? asItem(finding?.latest);
  const retestRows = Array.isArray(lineage?.retests) ? lineage.retests : Array.isArray(finding?.retests) ? finding.retests : [];
  const laterRows = Array.isArray(lineage?.later_same_pair) ? lineage.later_same_pair : [];
  return {
    originating: runRef(originating),
    retests: retestRows.map(asItem).filter((row) => textOf(row, 'intent') === 'retest' || textOf(row, 'relation') === 'retest').map(runRef).filter(Boolean),
    laterSamePair: laterRows.map(asItem).filter((row) => textOf(row, 'relation') === 'later_same_pair').map(runRef).filter(Boolean),
    latest: textOf(latest, 'test_run_id')
      ? {
        testRunId: textOf(latest, 'test_run_id'),
        relation: textOf(latest, 'relation'),
        status: textOf(latest, 'status'),
        finalized: typeof latest.finalized === 'boolean' ? latest.finalized : null,
        pending: latest.pending === true,
        completedAt: textOf(latest, 'completed_at'),
      }
      : null,
    closedAt: textOf(finding, 'closed_at') || textOf(lineage, 'closed_at'),
    siblingClosure: false,
  };
}
