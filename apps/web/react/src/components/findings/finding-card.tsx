import { findingStatus } from '../../lib/finding-lifecycle.mjs';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem } from '../../lib/types';
import { formatDate, formatSeverityLabel } from '../../lib/utils';
import { plainCheckName, plainFindingTitle, plainVerdictLabel } from '../../lib/plain-language.mjs';
import { Badge } from '../ui/badge';

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function verdictTone(verdict: string) {
  const key = verdict.trim().toLowerCase();
  if (['pass', 'passed', 'protected', 'resolved'].includes(key)) return 'success' as const;
  if (['gap', 'fail', 'failed', 'unprotected', 'bypassable'].includes(key)) return 'danger' as const;
  if (['partial', 'review', 'inconclusive'].includes(key)) return 'warn' as const;
  return 'info' as const;
}

export function FindingCard({
  finding,
  checks,
  targetGroups,
  targets,
  active = false,
  onOpen
}: {
  finding: DataItem;
  checks: DataItem[];
  targetGroups: DataItem[];
  targets: DataItem[];
  active?: boolean;
  onOpen?: (id: string) => void;
}) {
  const id = getString(finding, ['id'], '');
  const title = plainFindingTitle(finding, targets, checks);
  const severity = getString(finding, ['severity'], 'unknown');
  const state = findingStatus(finding);
  const verdict = getString(finding, ['verdict'], '');
  const checkId = getString(finding, ['check_id', 'check'], '');
  const check = checks.find((entry) => getString(entry, ['check_id', 'id']) === checkId);
  const checkLabel = checkId ? plainCheckName(getString(check ?? {}, ['name', 'title'], checkId)) : '';
  const groupId = getString(finding, ['target_group_id'], '');
  const group = targetGroups.find((entry) => getString(entry, ['id']) === groupId);
  const groupLabel = getString(group ?? {}, ['name', 'id'], groupId || 'Ungrouped');
  const openedAt = finding.created_at ?? finding.opened_at;
  const href = id ? buildDetailHref('finding-detail', id) : '#findings';

  return (
    <a
      className={`finding-card finding-row-primary${active ? ' is-active' : ''}`}
      href={href}
      data-focus-key={id ? `finding-${id}` : undefined}
      aria-current={active ? 'true' : undefined}
      aria-label={`${onOpen ? 'View evidence for finding' : 'Open finding'} ${title}, ${formatSeverityLabel(severity)}, ${state}`}
      onClick={(event) => {
        if (!id || !onOpen) return;
        event.preventDefault();
        onOpen(id);
      }}
    >
      <span className="fc-headline">
        <strong>{title}</strong>
        {verdict ? <Badge tone={verdictTone(verdict)} title={`Recorded verdict: ${plainVerdictLabel(verdict)}`}>{plainVerdictLabel(verdict)}</Badge> : null}
      </span>
      <span className="fc-meta mono" title={id}>{id || 'No finding ID'}</span>
      <span className="fc-facets">
        {checkLabel ? <span><span className="fc-key">Check:</span> {checkLabel}</span> : null}
        {checkLabel ? <span className="fc-sep" aria-hidden="true">·</span> : null}
        <span><span className="fc-key">Group:</span> {groupLabel}</span>
        <span className="fc-sep" aria-hidden="true">·</span>
        <span><span className="fc-key">Opened:</span> {formatDate(openedAt)}</span>
      </span>
    </a>
  );
}
