import { useEffect, useId, useState } from 'react';
import { listTargetRuns, type PvFailure, type RunSummary } from '../../../lib/protection-validation-api';
import type { PortalConfig, Session } from '../../../lib/types';
import { formatDate } from '../../../lib/utils';
import { runSelectionBlocker } from './presenter.mjs';
import { FailureNotice } from './shared';

type RunsState = { state: 'loading' } | { state: 'ready'; items: RunSummary[] } | { state: 'failed'; failure: PvFailure };

/** Choose recorded runs as evidence; only finalized runs on the allowed targets are selectable, and choosing never starts anything. */
export function RunPicker({
  config,
  session,
  legend,
  targetIds,
  selected,
  onChange,
  notBefore,
  error,
}: {
  config: PortalConfig;
  session: Session;
  legend: string;
  targetIds: string[];
  selected: string[];
  onChange: (ids: string[]) => void;
  notBefore?: string;
  error?: string;
}) {
  const id = useId();
  const [runs, setRuns] = useState<RunsState>({ state: 'loading' });
  const [reload, setReload] = useState(0);
  const key = targetIds.join('|');

  useEffect(() => {
    const controller = new AbortController();
    setRuns({ state: 'loading' });
    Promise.all(key.split('|').filter(Boolean).map((targetId) => listTargetRuns(config, session, targetId, controller.signal)))
      .then((results) => {
        if (controller.signal.aborted) return;
        for (const result of results) {
          if (result.state !== 'ready') { setRuns({ state: 'failed', failure: result }); return; }
        }
        const items = results.flatMap((result) => (result.state === 'ready' ? result.value : []));
        setRuns({ state: 'ready', items: items.sort((a, b) => (b.completed_at || b.created_at).localeCompare(a.completed_at || a.created_at)) });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, key, reload]);

  const notBeforeMs = notBefore ? Date.parse(notBefore) : NaN;

  return (
    <fieldset className="pv-picker" aria-describedby={`${id}-help`} aria-invalid={error ? true : undefined}>
      <legend>{legend}</legend>
      {runs.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading recorded runs" /> : null}
      {runs.state === 'failed' ? <FailureNotice failure={runs.failure} subject="recorded runs" onRetry={() => setReload((value) => value + 1)} /> : null}
      {runs.state === 'ready' && !runs.items.length ? <p className="td-muted small">No recorded run on these targets yet. Run the relevant checks first; selecting runs here never starts one.</p> : null}
      {runs.state === 'ready' && runs.items.length ? (
        <ul className="pv-runs">
          {runs.items.map((run) => {
            const blocker = runSelectionBlocker(run, targetIds);
            const finishedAt = run.completed_at || run.created_at;
            const older = Number.isFinite(notBeforeMs) && finishedAt && Date.parse(finishedAt) <= notBeforeMs;
            return (
              <li key={run.id}>
                <label className="pv-picker-option" aria-disabled={blocker ? true : undefined}>
                  <input
                    type="checkbox"
                    disabled={Boolean(blocker)}
                    checked={selected.includes(run.id)}
                    onChange={(event) => onChange(event.target.checked ? [...selected, run.id] : selected.filter((item) => item !== run.id))}
                  />
                  <span>
                    <span className="mono pv-break">{run.check_id || 'Check not recorded'}</span>
                    <span className="td-muted small mono pv-break">{run.id} · {run.target_id} · {run.status || 'status not recorded'}{finishedAt ? ` · ${formatDate(finishedAt)}` : ''}</span>
                    {blocker ? <span className="td-muted small">{blocker}</span> : null}
                    {!blocker && older ? <span className="td-form-error small">Not newer than the baseline; it will be reported as not comparable.</span> : null}
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
      ) : null}
      <span id={`${id}-help`} className={error ? 'td-form-error' : 'td-muted small'}>{error ?? 'The newest 100 runs per target are listed. Only finalized runs count as evidence.'}</span>
    </fieldset>
  );
}
