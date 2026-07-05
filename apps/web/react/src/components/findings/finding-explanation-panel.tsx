import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button } from '../ui/button';
import { VerdictExplanationPanel } from '../runs/run-proof-panels';
import { requestJson } from '../../lib/api';
import { resolveRemediationTemplate } from '../../lib/verdict-explanation';
import type { DataItem, PortalConfig, Session } from '../../lib/types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

const SKELETON_FIELD_COUNT = 4;

function DetailLoadingPlaceholder({ label = 'Loading linked run evidence…' }: { label?: string }) {
  return (
    <section
      className="verdict-explanation finding-explanation-loading"
      aria-busy="true"
      aria-label={label}
    >
      <span className="skeleton skeleton-text finding-explanation-loading-title" />
      <div className="verdict-explanation-grid">
        {Array.from({ length: SKELETON_FIELD_COUNT }, (_, index) => (
          <div key={index} className="verdict-explanation-item">
            <span className="skeleton skeleton-text" />
            <span className="skeleton skeleton-text skeleton-text-wide" />
          </div>
        ))}
      </div>
    </section>
  );
}

function buildFindingRunDetail(finding: DataItem | null, runDetail: DataItem | null) {
  if (!finding || !runDetail) return null;
  const detail = { ...runDetail };
  const findingTemplate = getString(finding, ['remediation_template'], '');
  const runTemplate = getString(runDetail, ['remediation_template'], '');
  const remediation = findingTemplate || runTemplate;
  if (remediation) {
    detail.remediation_template = remediation;
  }
  return detail;
}

export function FindingExplanationPanel({
  finding,
  config,
  session,
}: {
  finding: DataItem | null;
  config: PortalConfig;
  session: Session;
}) {
  const [runDetail, setRunDetail] = useState<DataItem | null>(null);
  const [runEvents, setRunEvents] = useState<DataItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState('');
  const [fetchGeneration, setFetchGeneration] = useState(0);

  const testRunId = getString(finding, ['test_run_id'], '');

  const loadRunEvidence = useCallback(() => {
    if (!testRunId) return;
    setFetchGeneration((value) => value + 1);
  }, [testRunId]);

  useEffect(() => {
    if (!testRunId) {
      setRunDetail(null);
      setRunEvents([]);
      setLoading(false);
      setFetchError('');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setFetchError('');
    Promise.all([
      requestJson(config, session, `/v1/test-runs/${testRunId}`),
      requestJson(config, session, `/v1/test-runs/${testRunId}/events`),
    ])
      .then(([detail, eventsPayload]) => {
        if (cancelled) return;
        setRunDetail(detail as DataItem);
        const items = Array.isArray((eventsPayload as { items?: unknown }).items)
          ? (eventsPayload as { items: DataItem[] }).items
          : [];
        setRunEvents(items);
      })
      .catch((err) => {
        if (!cancelled) {
          setRunDetail(null);
          setRunEvents([]);
          setFetchError(err instanceof Error ? err.message : 'Could not load linked run evidence.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [testRunId, config, session, fetchGeneration]);

  const explanationDetail = useMemo(
    () => buildFindingRunDetail(finding, runDetail),
    [finding, runDetail]
  );

  if (!finding) {
    return <p className="muted">Select a finding to review evidence-backed explanation.</p>;
  }

  if (!testRunId) {
    return (
      <section className="verdict-explanation verdict-explanation--pending">
        <h4>Why this finding?</h4>
        <p className="muted">This finding has no linked test run; probe and agent evidence cannot be loaded.</p>
        {getString(finding, ['notes'], '') ? (
          <div className="verdict-explanation-grid">
            <div className="verdict-explanation-item">
              <span className="verdict-explanation-label">Conclusion</span>
              <span className="verdict-explanation-value">{getString(finding, ['notes'])}</span>
            </div>
          </div>
        ) : null}
        {getString(finding, ['remediation_template'], '') ? (
          <div className="verdict-explanation-grid">
            <div className="verdict-explanation-item">
              <span className="verdict-explanation-label">Remediation</span>
              <span className="verdict-explanation-value">
                {resolveRemediationTemplate(getString(finding, ['remediation_template']), { finding })}
              </span>
            </div>
          </div>
        ) : null}
      </section>
    );
  }

  if (fetchError) {
    return (
      <div className="finding-explanation-panel">
        <div className="form-banner error stack-tight">
          <p>{fetchError}</p>
          <div className="row-actions">
            <Button size="sm" variant="secondary" onClick={() => loadRunEvidence()}>Retry</Button>
          </div>
        </div>
        {getString(finding, ['notes'], '') ? (
          <p className="muted">Finding notes: {getString(finding, ['notes'])}</p>
        ) : null}
      </div>
    );
  }

  if (loading && !explanationDetail) {
    return <DetailLoadingPlaceholder label="Loading linked run evidence for this finding…" />;
  }

  const runCheckLabel = getString(runDetail ?? {}, ['check_id'], '—');

  return (
    <div className="finding-explanation-panel">
      <p className="muted">
        Linked run {runDetail ? getString(runDetail, ['check_id'], testRunId) : testRunId}
        {runDetail ? ` · Check ${runCheckLabel}` : ''}
      </p>
      <VerdictExplanationPanel
        detail={explanationDetail}
        events={runEvents}
        finding={finding}
        heading="Why this finding?"
      />
    </div>
  );
}