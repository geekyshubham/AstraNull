import { useMemo, type ReactNode } from 'react';
import { ListChecks } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { VerifyChip } from '../../lib/verify-chip';
import { ONBOARDING_PLACEMENT_TEST_CHECK_ID } from '../../lib/onboarding';
import { formatPlacementStatus, placementStatusHint } from '../../lib/agent-helpers';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

const PLACEMENT_GATES = [
  'Bootstrap token exchanged for agent credential',
  'Protected-path canary observed on declared target group',
  'Probe and agent observations correlated under custody'
] as const;

function PtMetricCell({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="pt-cell">
      <div className="pt-label">{label}</div>
      <div className="pt-value mono">{value}</div>
    </div>
  );
}

function PlacementGateRow({ gate, pass }: { gate: string; pass: boolean }) {
  const status = pass ? 'pass' : 'pending';
  return (
    <li>
      <ListChecks size={14} aria-hidden="true" style={{ color: 'var(--fg-2)' }} />
      <span>{gate}</span>
      <Badge tone={pass ? 'success' : 'muted'} aria-label={`${gate}: ${status}`}>
        {status}
      </Badge>
    </li>
  );
}

type PlacementOutcome = 'pass' | 'fail' | 'review' | 'unknown';

/**
 * Extract the real placement verdict from a test-run record. Prefers the nested
 * verdict object (`run.verdict.verdict`), then a string verdict field. It never
 * treats the lifecycle status (e.g. `verdicted`, `completed`) as a verdict on its
 * own — that conflation was the P1#10 false-positive.
 */
function placementVerdictString(run: DataItem | null): string {
  if (!run) return '';
  const direct = run.verdict;
  if (typeof direct === 'string') return direct;
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) {
    const nested = direct as DataItem;
    const value = nested.verdict ?? nested.status;
    if (typeof value === 'string') return value;
  }
  return '';
}

/** Canonical run-verdict classification (mirrors lib/readiness-posture + charts/score-trend). */
function classifyPlacementVerdict(verdict: string): PlacementOutcome {
  const key = verdict.trim().toLowerCase();
  if (!key || ['pending', 'planned', 'queued', 'scheduled', 'running', 'collecting', 'in_progress'].includes(key)) {
    return 'unknown';
  }
  if (['pass', 'passed', 'protected', 'edge_protected', 'allowed_as_expected', 'proven', 'success', 'ok'].includes(key)) {
    return 'pass';
  }
  if (
    ['gap', 'fail', 'failed', 'error', 'aborted', 'canceled', 'cancelled', 'timeout', 'danger', 'penetrated', 'bypassable', 'edge_exposed', 'unprotected'].includes(key)
  ) {
    return 'fail';
  }
  // review bucket: warn / inconclusive / misplaced_agent / underprotected / unknown / unrecognized.
  return 'review';
}

/**
 * Resolve the placement outcome from the latest placement run. `pass` is returned
 * ONLY when the run's published verdict is a passing verdict — never from lifecycle
 * status alone. This is the P1#10 fix: a finalized-but-failed run no longer shows pass.
 */
function resolvePlacementOutcome(run: DataItem | null): PlacementOutcome {
  if (!run) return 'unknown';
  const status = getString(run, ['status'], '').trim().toLowerCase();
  if (['queued', 'scheduled', 'planned', 'pending', 'running', 'collecting', 'in_progress'].includes(status)) {
    return 'unknown';
  }
  const verdictValue = placementVerdictString(run);
  if (verdictValue) return classifyPlacementVerdict(verdictValue);
  if (['canceled', 'cancelled', 'error', 'failed', 'aborted', 'timeout'].includes(status)) return 'fail';
  // Finalized without a surfaced verdict payload → needs review, never an implicit pass.
  return 'review';
}

function PlacementVerdictChip({ outcome, provenance }: { outcome: PlacementOutcome; provenance: string }) {
  if (outcome === 'pass') {
    return (
      <span className="verify-chip is-verified" title={provenance} aria-label={`Placement verified — last run passed. ${provenance}`}>
        <span className="vc-dot" aria-hidden="true" />
        last run · pass
      </span>
    );
  }
  if (outcome === 'fail') {
    return (
      <Badge tone="danger" title={provenance} aria-label={`Placement failed on last run. ${provenance}`}>
        last run · fail
      </Badge>
    );
  }
  if (outcome === 'review') {
    return (
      <Badge tone="warn" title={provenance} aria-label={`Placement needs review after last run. ${provenance}`}>
        last run · review
      </Badge>
    );
  }
  return <VerifyChip state="pending" provenance={provenance} />;
}

export function AgentPlacementPanel({
  agent,
  agentId,
  targetGroupId,
  runs,
  placementReview,
  onRunPlacement,
  running,
  busy
}: {
  agent: DataItem;
  agentId: string;
  targetGroupId: string;
  runs: DataItem[];
  placementReview: DataItem | null;
  onRunPlacement: () => void;
  running?: boolean;
  busy?: boolean;
}) {
  const placementRun = useMemo(
    () =>
      runs
        .filter((run) => getString(run, ['check_id']) === ONBOARDING_PLACEMENT_TEST_CHECK_ID)
        .sort((a, b) =>
          String(b.started_at ?? b.created_at ?? '').localeCompare(String(a.started_at ?? a.created_at ?? ''))
        )[0] ?? null,
    [runs]
  );

  const outcome = resolvePlacementOutcome(placementRun);
  const pass = outcome === 'pass';
  const verdictValue = placementVerdictString(placementRun);
  const lifecycleStatus = getString(placementRun, ['status'], 'pending');
  const provenance = placementRun
    ? `Placement test ${getString(placementRun, ['id'])} · verdict ${verdictValue || '(none published)'} · status ${lifecycleStatus} · outcome ${outcome} from test-runs API.`
    : 'No placement test run recorded for this agent scope.';

  const runDisabled = busy || !targetGroupId;
  const runLabel = targetGroupId
    ? 'Run placement test for this agent'
    : 'Run placement test (select a target group first)';

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Placement test</CardTitle>
          <CardDescription>Bounded protected-path canary. Metadata-only signal under custody.</CardDescription>
        </div>
        <div className="row-actions">
          <PlacementVerdictChip outcome={outcome} provenance={provenance} />
          <Button
            size="sm"
            loading={running}
            disabled={runDisabled}
            onClick={onRunPlacement}
            aria-label={runLabel}
          >
            Run placement test
          </Button>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="pt-grid">
          <PtMetricCell
            label="Last test"
            value={placementRun ? formatDate(placementRun.started_at ?? placementRun.created_at) : '—'}
          />
          <PtMetricCell
            label="Duration"
            value={getString(placementRun, ['duration_ms', 'duration'], '—')}
          />
          <PtMetricCell
            label="Signal"
            value={getString(placementReview, ['observation_mode'], getString(agent, ['placement_type'], '—'))}
          />
          <PtMetricCell
            label="Evidence"
            value={placementRun ? getString(placementRun, ['id']) : '—'}
          />
        </div>
        <ul className="placement-gates" aria-label="Placement verification gates">
          {PLACEMENT_GATES.map((gate) => (
            <PlacementGateRow key={gate} gate={gate} pass={pass} />
          ))}
        </ul>
        {placementReview ? (
          <p className="muted" title={placementStatusHint(getString(placementReview, ['status'])) || undefined}>
            Placement review: {formatPlacementStatus(getString(placementReview, ['status']))} ·{' '}
            {getString(placementReview, ['summary'], '—')}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}