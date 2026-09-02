import type { BadgeProps } from '../components/ui/badge';

export type StatusTone = NonNullable<BadgeProps['tone']>;

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
  const key = status.trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (['completed', 'verdicted', 'finalized', 'succeeded', 'pass'].includes(key)) return 'success';
  if (['running', 'collecting', 'pending', 'queued'].includes(key)) return 'info';
  if (['cancelled', 'canceled', 'failed', 'error'].includes(key)) return 'danger';
  if (['stopped', 'stopping'].includes(key)) return 'warn';
  if (key === 'planned') return 'muted';
  return 'warn';
}
