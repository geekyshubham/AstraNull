import { useCallback, useEffect, useMemo, useState } from 'react';
import { AnchorButton, Button } from '../ui/button';
import { ExplanationField, VerdictExplanationPanel } from '../runs/run-proof-panels';
import { requestJson } from '../../lib/api';
import { buildDetailHref } from '../../lib/route-params';
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

function isDataItem(value: unknown): value is DataItem {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

const SKELETON_FIELD_COUNT = 4;

type LinkedRunEvidenceState = {
  runId: string;
  status: 'idle' | 'loading' | 'loaded' | 'error';
  detail: DataItem | null;
  events: DataItem[];
  error: string;
};

const EMPTY_RUN_EVIDENCE: LinkedRunEvidenceState = {
  runId: '',
  status: 'idle',
  detail: null,
  events: [],
  error: '',
};

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
  const [runEvidence, setRunEvidence] = useState<LinkedRunEvidenceState>(EMPTY_RUN_EVIDENCE);
  const [fetchGeneration, setFetchGeneration] = useState(0);

  const testRunId = getString(finding, ['test_run_id'], '');
  const visibleRunEvidence = runEvidence.runId === testRunId
    ? runEvidence
    : {
        ...EMPTY_RUN_EVIDENCE,
        runId: testRunId,
        status: testRunId ? 'loading' as const : 'idle' as const,
      };

  const loadRunEvidence = useCallback(() => {
    if (!testRunId) return;
    setRunEvidence({
      ...EMPTY_RUN_EVIDENCE,
      runId: testRunId,
      status: 'loading',
    });
    setFetchGeneration((value) => value + 1);
  }, [testRunId]);

  useEffect(() => {
    if (!testRunId) {
      setRunEvidence(EMPTY_RUN_EVIDENCE);
      return;
    }

    const requestedRunId = testRunId;
    let cancelled = false;
    setRunEvidence({
      ...EMPTY_RUN_EVIDENCE,
      runId: requestedRunId,
      status: 'loading',
    });
    Promise.all([
      requestJson(config, session, `/v1/test-runs/${encodeURIComponent(requestedRunId)}`),
      requestJson(config, session, `/v1/test-runs/${encodeURIComponent(requestedRunId)}/events`),
    ])
      .then(([detailPayload, eventsPayload]) => {
        if (cancelled) return;
        if (!isDataItem(detailPayload)) {
          throw new Error('The linked run returned an invalid detail record.');
        }
        const returnedRunId = getString(detailPayload, ['id', 'test_run_id'], '');
        if (returnedRunId !== requestedRunId) {
          throw new Error('The linked run response did not match this finding.');
        }
        if (!isDataItem(eventsPayload) || !Array.isArray(eventsPayload.items)) {
          throw new Error('The linked run returned an invalid event log.');
        }
        if (!eventsPayload.items.every(isDataItem)) {
          throw new Error('The linked run event log contained invalid records.');
        }
        const events = eventsPayload.items as DataItem[];
        if (events.some((event) => {
          const eventRunId = getString(event, ['test_run_id'], '');
          return eventRunId !== '' && eventRunId !== requestedRunId;
        })) {
          throw new Error('The linked run event log contained records from another run.');
        }
        setRunEvidence({
          runId: requestedRunId,
          status: 'loaded',
          detail: detailPayload,
          events,
          error: '',
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setRunEvidence({
            ...EMPTY_RUN_EVIDENCE,
            runId: requestedRunId,
            status: 'error',
            error: err instanceof Error ? err.message : 'Could not load linked run evidence.',
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [testRunId, config, session, fetchGeneration]);

  const explanationDetail = useMemo(
    () => buildFindingRunDetail(finding, visibleRunEvidence.detail),
    [finding, visibleRunEvidence.detail]
  );

  if (!finding) {
    return <p className="muted">Select a finding to review evidence-backed explanation.</p>;
  }

  if (!testRunId) {
    return (
      <section className="verdict-explanation verdict-explanation--pending">
        <h3>Linked evidence unavailable</h3>
        <p className="muted">This finding does not identify an originating test run, so probe and agent evidence cannot be attributed.</p>
        {getString(finding, ['notes'], '') ? (
          <div className="verdict-explanation-grid">
            <ExplanationField label="Finding note — not linked run evidence" value={getString(finding, ['notes'])} fullWidth />
          </div>
        ) : null}
        {getString(finding, ['remediation_template'], '') ? (
          <div className="verdict-explanation-grid">
            <ExplanationField
              label="Recorded remediation"
              value={resolveRemediationTemplate(getString(finding, ['remediation_template']), { finding })}
              fullWidth
            />
          </div>
        ) : null}
      </section>
    );
  }

  if (visibleRunEvidence.status === 'error') {
    return (
      <div className="finding-explanation-panel">
        <div className="form-banner error stack-tight" role="alert">
          <strong>Linked run evidence could not be loaded.</strong>
          <p>{visibleRunEvidence.error}</p>
          <p className="muted">The run and its event log remain unavailable; no empty evidence set is being treated as trusted.</p>
          <div className="row-actions">
            <Button size="sm" variant="secondary" onClick={loadRunEvidence}>Retry evidence load</Button>
          </div>
        </div>
        <div className="verdict-explanation-grid" aria-label="Unverified finding provenance">
          <ExplanationField label="Originating run requested by finding" value={testRunId} />
          {getString(finding, ['notes'], '') ? (
            <ExplanationField label="Finding note — not linked run evidence" value={getString(finding, ['notes'])} />
          ) : null}
        </div>
      </div>
    );
  }

  if (visibleRunEvidence.status === 'loading' || !explanationDetail) {
    return <DetailLoadingPlaceholder label={`Loading linked run ${testRunId} and its event evidence…`} />;
  }

  const findingId = getString(finding, ['id'], '');
  const linkedRunId = getString(visibleRunEvidence.detail, ['id', 'test_run_id'], testRunId);
  const runCheckId = getString(visibleRunEvidence.detail, ['check_id'], '');
  const eventCount = visibleRunEvidence.events.length;

  return (
    <div className="finding-explanation-panel">
      <section className="verdict-explanation" aria-label="Finding evidence provenance">
        <h3>Evidence provenance</h3>
        <div className="verdict-explanation-grid">
          <ExplanationField label="Finding record" value={findingId || 'Not recorded on finding'} />
          <ExplanationField label="Originating run" value={linkedRunId} />
          <ExplanationField label="Run check" value={runCheckId || 'Not recorded on linked run'} />
          <ExplanationField label="Run event records" value={`${eventCount} loaded from linked run`} />
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', linkedRunId)}>
            Open linked run
          </AnchorButton>
        </div>
      </section>
      <VerdictExplanationPanel
        detail={explanationDetail}
        events={visibleRunEvidence.events}
        finding={finding}
        heading="Why this finding?"
      />
    </div>
  );
}
