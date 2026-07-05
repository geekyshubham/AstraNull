import { useEffect, useMemo, useState } from 'react';
import { VerdictExplanationPanel } from '../runs/run-proof-panels';
import { requestJson } from '../../lib/api';
import type { DataItem, PortalConfig, Session } from '../../lib/types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function buildFindingRunDetail(finding: DataItem | null, runDetail: DataItem | null) {
  if (!finding || !runDetail) return null;
  const detail = { ...runDetail };
  const remediation = getString(finding, ['remediation_template'], '');
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

  const testRunId = getString(finding, ['test_run_id'], '');

  useEffect(() => {
    if (!testRunId) {
      setRunDetail(null);
      setRunEvents([]);
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
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
      .catch(() => {
        if (!cancelled) {
          setRunDetail(null);
          setRunEvents([]);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [testRunId, config, session]);

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
              <span className="verdict-explanation-value">{getString(finding, ['remediation_template'])}</span>
            </div>
          </div>
        ) : null}
      </section>
    );
  }

  if (loading && !explanationDetail) {
    return <p className="muted">Loading linked run evidence for this finding...</p>;
  }

  return (
    <div className="finding-explanation-panel">
      <p className="muted">
        Run <code>{testRunId}</code>
        {runDetail ? ` · Check ${getString(runDetail, ['check_id'], '—')}` : ''}
      </p>
      <VerdictExplanationPanel detail={explanationDetail} events={runEvents} heading="Why this finding?" />
    </div>
  );
}