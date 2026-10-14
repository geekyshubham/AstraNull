import type { BadgeProps } from '../components/ui/badge';

export type StatusTone = NonNullable<BadgeProps['tone']>;

/** One status-key normalization for every tone helper: lower snake case. */
export function statusKey(value: unknown): string {
  return String(value ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

/**
 * One run-lifecycle status vocabulary for every surface.
 *
 * This existed as three separate copies — the runs list, the dashboard, and the
 * run detail page — and they had drifted: only two of them classified
 * `completed`, so the same finished run showed a green chip on its detail page
 * and an amber (attention) chip in the list it was opened from. Status colour is
 * the signal an operator scans for, so it cannot depend on which surface is
 * being read.
 */
export function runStatusTone(status: string): StatusTone {
  const key = statusKey(status);
  if (['completed', 'verdicted', 'finalized', 'succeeded', 'pass'].includes(key)) return 'success';
  if (['running', 'collecting'].includes(key)) return 'warn';
  if (['pending', 'queued'].includes(key)) return 'muted';
  if (['cancelled', 'canceled', 'failed', 'error'].includes(key)) return 'danger';
  if (['stopped', 'stopping'].includes(key)) return 'warn';
  if (key === 'planned') return 'muted';
  return 'warn';
}

/** Finding lifecycle tone: resolved states read green, open work amber, dismissed states muted. */
export function findingStatusTone(status: string | null | undefined): StatusTone {
  const key = statusKey(status);
  if (['closed', 'resolved', 'fix_verified'].includes(key)) return 'success';
  if (['open', 'in_progress', 'remediation_pending', 'reopened'].includes(key)) return 'warn';
  return 'muted';
}

/** Report lifecycle tone: a finished report reads green, a failed one red, everything else neutral. */
export function reportStatusTone(status: string | null | undefined): StatusTone {
  const key = statusKey(status);
  if (['ready', 'published', 'complete', 'completed'].includes(key)) return 'success';
  if (['failed', 'error'].includes(key)) return 'danger';
  return 'muted';
}

/** High-scale request lifecycle: live or awaiting work is amber, a halted run needs attention, outcomes are final. */
export function highScaleStateTone(state: string | null | undefined): StatusTone {
  const key = statusKey(state);
  if (['completed', 'closed', 'executed'].includes(key)) return 'success';
  if (['rejected', 'failed'].includes(key)) return 'danger';
  if (['running', 'executing', 'active', 'started', 'stopped', 'submitted', 'under_review', 'soc_review', 'pending', 'draft'].includes(key)) return 'warn';
  return 'muted';
}

/** Authorization artifact review: an expired or rejected artifact is no longer valid evidence. */
export function artifactReviewTone(status: string | null | undefined): StatusTone {
  const key = statusKey(status);
  if (key === 'accepted') return 'success';
  if (['rejected', 'expired'].includes(key)) return 'danger';
  if (['not_required', 'waived'].includes(key)) return 'muted';
  return 'warn';
}

const PASS_VERDICTS = ['pass', 'passed', 'success', 'ok', 'covered', 'protected', 'resolved', 'ready'];
const GAP_VERDICTS = ['fail', 'failed', 'gap', 'edge_exposed', 'bypassable', 'penetrated', 'exposed', 'unprotected'];
const REVIEW_VERDICTS = ['review', 'needs_review', 'manual_review', 'warn', 'warning', 'partial', 'inconclusive', 'needs_evidence'];

/** Evidence-backed verdict tone: pass green, gap red, needs-review amber, anything else neutral. */
export function verdictTone(verdict: string | null | undefined): StatusTone {
  const key = statusKey(verdict);
  if (PASS_VERDICTS.includes(key)) return 'success';
  if (GAP_VERDICTS.includes(key)) return 'danger';
  if (REVIEW_VERDICTS.includes(key)) return 'warn';
  return 'muted';
}

/** Subscription status: active is healthy, payment or pause issues need attention, ended or suspended is adverse. */
export function subscriptionStatusTone(status: string | null | undefined): StatusTone {
  const key = statusKey(status);
  if (['active', 'trialing'].includes(key)) return 'success';
  if (['past_due', 'paused'].includes(key)) return 'warn';
  if (['canceled', 'cancelled', 'suspended'].includes(key)) return 'danger';
  return 'muted';
}

/** Tenant lifecycle: active is healthy, suspended is adverse, pending needs attention, unrecorded stays neutral. */
export function tenantLifecycleTone(state: string | null | undefined): StatusTone {
  const key = statusKey(state);
  if (key === 'active') return 'success';
  if (key === 'suspended') return 'danger';
  if (key === 'pending') return 'warn';
  return 'muted';
}
