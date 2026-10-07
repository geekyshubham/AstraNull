import { useCallback, useState } from 'react';
import { ExternalLink } from 'lucide-react';
import type { EvidenceRef, PvFailure } from '../../../lib/protection-validation-api';
import type { Session } from '../../../lib/types';
import { formatDate } from '../../../lib/utils';
import { useOpenInspector } from '../../evidence/use-inspector';
import { Button } from '../../ui/button';
import { failureCopy, limitationLabels } from './presenter.mjs';

const STORAGE_PREFIX = 'astranull.pv.selection';

function storageKey(session: Session, scope: string, key: string) {
  return `${STORAGE_PREFIX}.${session.tenant_id ?? ''}.${session.user_id ?? ''}.${scope}.${key}`;
}

/** Selection kept by id in session storage so a refresh or a data reload never moves it. */
export function useStickySelection(session: Session, scope: string, key: string): [string, (next: string) => void] {
  const fullKey = storageKey(session, scope, key);
  const [value, setValue] = useState(() => {
    try {
      return window.sessionStorage.getItem(fullKey) ?? '';
    } catch {
      return '';
    }
  });
  const update = useCallback((next: string) => {
    setValue(next);
    try {
      if (next) window.sessionStorage.setItem(fullKey, next);
      else window.sessionStorage.removeItem(fullKey);
    } catch {
      // Storage can be unavailable in private modes; the in-memory selection still holds.
    }
  }, [fullKey]);
  return [value, update];
}

export function FailureNotice({ failure, subject, onRetry }: { failure: PvFailure; subject: string; onRetry?: () => void }) {
  const tone = failure.state === 'unsupported' || failure.state === 'disabled' || failure.state === 'forbidden' ? 'muted' : 'warn';
  const retryable = failure.state === 'transport_error' || failure.state === 'unavailable';
  return (
    <p className="pv-notice" data-tone={tone} data-state={failure.state} role={tone === 'warn' ? 'alert' : 'status'}>
      <span>{failureCopy(failure, subject)}</span>
      {retryable && onRetry ? <Button size="sm" variant="ghost" onClick={onRetry}>Retry</Button> : null}
    </p>
  );
}

export function LimitationList({ values, label = 'Limitations' }: { values: string[]; label?: string }) {
  const items = limitationLabels(values);
  if (!items.length) return null;
  return (
    <ul className="pv-limits" aria-label={label}>
      {items.map((item) => <li key={item.id}>{item.label}</li>)}
    </ul>
  );
}

/** Reference-only evidence links; opening one reads the recorded run and never starts a check. */
export function EvidenceRefList({ refs, focusPrefix }: { refs: EvidenceRef[]; focusPrefix: string }) {
  const openInspector = useOpenInspector();
  if (!refs.length) return <p className="td-muted small">No finalized evidence is linked yet.</p>;
  return (
    <ul className="pv-refs" aria-label="Linked evidence">
      {refs.map((ref, index) => {
        const focusKey = `${focusPrefix}-${ref.test_run_id}-${index}`;
        return (
          <li key={focusKey} className="pv-ref">
            <div className="pv-actions">
              <span className="pv-break">{ref.check_id || 'Check not recorded'}</span>
              {ref.check_version ? <code>v{ref.check_version}</code> : null}
              <span className="td-muted small">{ref.observed_at ? formatDate(ref.observed_at) : 'Time not recorded'}</span>
            </div>
            <code>run {ref.test_run_id} · target {ref.target_id || 'not recorded'} · source {ref.source_perspective || 'not recorded'} · worker {ref.worker_id || 'not recorded'}</code>
            {ref.evidence_ids.length ? <code>evidence {ref.evidence_ids.join(', ')}</code> : null}
            <div className="pv-actions">
              {ref.finalized ? null : <span className="td-muted small">Not finalized; not counted as evidence.</span>}
              {ref.target_id && ref.check_id ? (
                <Button
                  size="sm"
                  variant="ghost"
                  data-focus-key={focusKey}
                  onClick={() => openInspector({ entry: 'check_result', target_id: ref.target_id, check_id: ref.check_id, test_run_id: ref.test_run_id }, focusKey)}
                >
                  <ExternalLink size={14} aria-hidden="true" />Inspect evidence
                </Button>
              ) : null}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
