import { ShieldCheck, TriangleAlert } from 'lucide-react';
import { useEffect, useId, useMemo, useState } from 'react';
import { requestJson } from '../../lib/api';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName } from '../../lib/plain-language.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { asArray } from '../../lib/utils';
import type {
  ResourceFamily,
  ResourceFamilyVerdictState,
  ResourceMatrixStatus,
} from '../../lib/resource-matrix.d.mts';
import {
  RESOURCE_EVIDENCE_FRESHNESS_DAYS,
  RESOURCE_FAMILIES,
  applicableResourceFamilyCheckIds,
  resourceFamilyCheckIds,
  resourceFamilyVerdictState,
  resourceMatrixGroups,
} from '../../lib/resource-matrix.mjs';
import { Badge } from '../ui/badge';
import { EmptyState } from '../ui/empty-state';
import './charts.css';

type ResourceMatrixProps = {
  checks: Record<string, unknown>[];
  targetGroups: Record<string, unknown>[];
  runs: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
  config: PortalConfig;
  session: Session;
  dataLoadError?: string | null;
  onRefresh?: () => Promise<void>;
};

type HydrationState =
  | { status: 'loading'; targets: Record<string, unknown>[]; runs: Record<string, unknown>[] }
  | { status: 'ready'; targets: Record<string, unknown>[]; runs: Record<string, unknown>[] }
  | { status: 'error'; targets: Record<string, unknown>[]; runs: Record<string, unknown>[] };

const TERMINAL_RUN_STATUSES = new Set(['completed', 'verdicted']);
const DETAIL_CONCURRENCY = 6;

const STATUS_TONE: Record<ResourceMatrixStatus, 'success' | 'warn' | 'danger' | 'muted'> = {
  protected: 'success',
  exposed: 'danger',
  inconclusive: 'warn',
  stale: 'warn',
  not_run: 'muted',
  not_applicable: 'muted',
};

const READINESS_STATUS_LABEL: Record<ResourceMatrixStatus, string> = {
  protected: 'Protected',
  exposed: 'Exposed',
  inconclusive: 'Inconclusive',
  stale: 'Stale',
  not_run: 'Not run',
  not_applicable: 'Not applicable',
};

const VALIDATION_STATUS_LABEL: Record<ResourceMatrixStatus, string> = {
  protected: 'Passing evidence',
  exposed: 'Finding',
  inconclusive: 'Inconclusive',
  stale: 'Stale',
  not_run: 'Not validated',
  not_applicable: 'Not applicable',
};

function statusLabel(family: ResourceFamily, status: ResourceMatrixStatus) {
  return family.visualization === 'readiness_posture'
    ? READINESS_STATUS_LABEL[status]
    : VALIDATION_STATUS_LABEL[status];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function recordId(item: Record<string, unknown>) {
  return String(item.id ?? item.test_run_id ?? '');
}

function checkId(item: Record<string, unknown>) {
  const nested = asRecord(item.check);
  return String(item.check_id ?? item.checkId ?? nested?.check_id ?? '');
}

function groupId(item: Record<string, unknown>) {
  const nested = asRecord(item.target_group);
  return String(item.target_group_id ?? item.targetGroupId ?? nested?.id ?? '');
}

function evidenceRunId(item: Record<string, unknown>) {
  return String(item.test_run_id ?? item.testRunId ?? '');
}

function hasStoredVerdict(item: Record<string, unknown>) {
  return asRecord(item.verdict) !== null;
}

function itemsFromPayload(payload: unknown) {
  if (Array.isArray(payload)) return payload as Record<string, unknown>[];
  const record = asRecord(payload);
  if (!record || !Array.isArray(record.items)) throw new Error('invalid_list_payload');
  return asArray<Record<string, unknown>>(record);
}

async function hydrateRunDetails(
  ids: string[],
  config: PortalConfig,
  session: Session,
) {
  const details: Record<string, unknown>[] = [];
  for (let offset = 0; offset < ids.length; offset += DETAIL_CONCURRENCY) {
    const batch = ids.slice(offset, offset + DETAIL_CONCURRENCY);
    const rows = await Promise.all(batch.map(async (id) => {
      const payload = await requestJson(config, session, `/v1/test-runs/${encodeURIComponent(id)}`);
      const row = asRecord(payload);
      if (!row || recordId(row) !== id) throw new Error('invalid_run_detail');
      return row;
    }));
    details.push(...rows);
  }
  return details;
}

function mergedRuns(
  listRuns: Record<string, unknown>[],
  details: Record<string, unknown>[],
) {
  const byId = new Map<string, Record<string, unknown>>();
  const withoutId: Record<string, unknown>[] = [];
  for (const run of listRuns) {
    const id = recordId(run);
    if (id) byId.set(id, run);
    else withoutId.push(run);
  }
  for (const detail of details) byId.set(recordId(detail), detail);
  return [...withoutId, ...byId.values()];
}

function latestLabel(value: string | null) {
  if (!value) return 'No usable evidence timestamp';
  return `Latest evidence ${new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(value))}`;
}

function cellDescription(family: ResourceFamily, state: ResourceFamilyVerdictState) {
  const scope = family.scoredForDdosReadiness
    ? 'Included in DDoS readiness posture.'
    : 'Validation-only coverage; excluded from DDoS readiness scoring.';
  if (state.status === 'not_applicable') {
    return `${plainCheckName(family.label)}: no mapped checks support this target group's declared target kinds. ${family.description} ${scope}`;
  }
  if (state.status === 'not_run') {
    return `${plainCheckName(family.label)}: no stored verdict found in the loaded records for ${state.applicableCheckCount} applicable checks. ${family.description} ${scope}`;
  }
  return `${plainCheckName(family.label)} (${family.metric}): ${statusLabel(family, state.status)}. ${state.testedCheckCount} of ${state.applicableCheckCount} applicable checks tested; ${state.freshCheckCount} fresh and ${state.staleCheckCount} stale. ${latestLabel(state.latestEvidenceAt)}. ${scope}`;
}

function MatrixCell({
  family,
  state,
}: {
  family: ResourceFamily;
  state: ResourceFamilyVerdictState;
}) {
  const description = cellDescription(family, state);
  const count = state.status === 'not_applicable'
    ? '0 applicable'
    : `${state.testedCheckCount}/${state.applicableCheckCount} tested`;
  return (
    <span
      className={`heatmap-cell heatmap-${STATUS_TONE[state.status]} matrix-cell`}
      data-status={state.status}
      title={description}
      aria-label={description}
    >
      <strong>{statusLabel(family, state.status)}</strong>
      <small>{count}</small>
    </span>
  );
}

function MatrixSkeleton({ columns, rows }: { columns: number; rows: number }) {
  const style = { ['--skeleton-cols' as string]: Math.min(columns, 6) };
  return (
    <div className="chart-skeleton" role="status" aria-live="polite" style={style}>
      <span className="sr-only">Loading declared targets and stored verdict details before calculating posture.</span>
      {[0, ...Array.from({ length: Math.max(1, Math.min(rows, 4)) }, (_unused, index) => index + 1)].map((row) => (
        <div className={row === 0 ? 'chart-skeleton-row is-head' : 'chart-skeleton-row'} key={row} aria-hidden="true">
          {Array.from({ length: Math.min(columns, 6) + 1 }, (_unused, cell) => (
            <span className="skeleton" key={cell} />
          ))}
        </div>
      ))}
    </div>
  );
}

function MatrixLegend() {
  return (
    <div className="heatmap-legend" aria-label="Matrix status legend">
      <Badge tone="success">Protected / passing evidence</Badge>
      <Badge tone="danger">Exposed / finding</Badge>
      <Badge tone="warn">Inconclusive</Badge>
      <Badge tone="warn">Stale</Badge>
      <Badge tone="muted">Not run / not validated</Badge>
      <Badge tone="muted">Not applicable</Badge>
    </div>
  );
}

export function ResourceMatrix({
  checks,
  targetGroups,
  runs,
  evidence,
  config,
  session,
  dataLoadError = null,
  onRefresh,
}: ResourceMatrixProps) {
  const descriptionId = useId();
  const groups = useMemo(() => resourceMatrixGroups(targetGroups), [targetGroups]);
  const readinessFamilyCount = RESOURCE_FAMILIES.filter((family) => family.scoredForDdosReadiness).length;
  const validationFamilyCount = RESOURCE_FAMILIES.length - readinessFamilyCount;
  const mappedCheckIds = useMemo(() => {
    const ids = new Set<string>();
    for (const family of RESOURCE_FAMILIES) {
      for (const id of resourceFamilyCheckIds(checks, family)) ids.add(id);
    }
    return ids;
  }, [checks]);
  const [attempt, setAttempt] = useState(0);
  const [hydration, setHydration] = useState<HydrationState>({
    status: 'loading',
    targets: [],
    runs: [],
  });

  useEffect(() => {
    let cancelled = false;
    if (groups.length === 0 || mappedCheckIds.size === 0) {
      setHydration({ status: 'ready', targets: [], runs });
      return () => { cancelled = true; };
    }
    if (dataLoadError) {
      setHydration({ status: 'error', targets: [], runs: [] });
      return () => { cancelled = true; };
    }

    setHydration((current) => ({ ...current, status: 'loading' }));
    const activeGroupIds = new Set(groups.map((group) => String(group.id ?? '')).filter(Boolean));
    const listedById = new Map<string, Record<string, unknown>>();
    for (const run of runs) {
      const id = recordId(run);
      if (id) listedById.set(id, run);
    }
    const detailIds = new Set<string>();

    for (const run of runs) {
      const status = String(run.status ?? '').toLowerCase();
      if (
        !TERMINAL_RUN_STATUSES.has(status)
        || !activeGroupIds.has(groupId(run))
        || !mappedCheckIds.has(checkId(run))
      ) continue;
      const id = recordId(run);
      if (!id) {
        setHydration({ status: 'error', targets: [], runs: [] });
        return () => { cancelled = true; };
      }
      if (!hasStoredVerdict(run)) detailIds.add(id);
    }
    // Evidence rows do not reliably carry check/group ids. Hydrating their bound run prevents
    // such rows from being silently dropped merely because the bounded run list omitted them.
    for (const item of evidence) {
      const id = evidenceRunId(item);
      if (id && !hasStoredVerdict(listedById.get(id) ?? {})) detailIds.add(id);
    }

    void Promise.all([
      requestJson(config, session, '/v1/targets').then(itemsFromPayload),
      hydrateRunDetails([...detailIds], config, session),
    ])
      .then(([targets, details]) => {
        if (!cancelled) {
          setHydration({ status: 'ready', targets, runs: mergedRuns(runs, details) });
        }
      })
      .catch(() => {
        if (!cancelled) setHydration({ status: 'error', targets: [], runs: [] });
      });

    return () => { cancelled = true; };
  }, [attempt, checks, config, dataLoadError, evidence, groups, mappedCheckIds, runs, session]);

  const retry = () => {
    void (async () => {
      try {
        await onRefresh?.();
      } finally {
        setAttempt((value) => value + 1);
      }
    })();
  };

  if (dataLoadError || hydration.status === 'error') {
    return (
      <EmptyState
        icon={TriangleAlert}
        title="Resource matrix unavailable."
        body="Target applicability or required verdict details could not be loaded. No posture is shown because partial data could be misleading."
        actionLabel="Retry matrix"
        onAction={retry}
      />
    );
  }

  if (groups.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No declared target groups yet."
        body="Resource-exhaustion posture is assessed per active target group. Declare one to evaluate applicable checks."
      />
    );
  }

  if (mappedCheckIds.size === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No resource-exhaustion checks are mapped."
        body="The check catalog loaded, but none of its entries declares an exhausted-resource family."
      />
    );
  }

  if (hydration.status === 'loading') {
    return <MatrixSkeleton columns={RESOURCE_FAMILIES.length} rows={groups.length} />;
  }

  return (
    <>
      <p id={descriptionId} className="matrix-intro">
        Every shipped exhausted-resource family is shown: {readinessFamilyCount} availability families contribute to DDoS readiness posture and {validationFamilyCount} application-security families show validation coverage only.
        Each cell uses the latest evidence-referenced stored verdict per applicable check. Evidence is fresh for {RESOURCE_EVIDENCE_FRESHNESS_DAYS} days.
        Protected or passing evidence requires a fresh pass for every applicable check; partial coverage remains inconclusive.
      </p>
      <div
        className="heatmap"
        role="region"
        aria-label={`Resource-exhaustion verdict matrix for ${groups.length} target groups`}
        aria-describedby={descriptionId}
        tabIndex={0}
      >
        <table className="matrix-table matrix-table--resource">
          <caption>
            All {groups.length} active target groups across all {RESOURCE_FAMILIES.length} shipped exhausted-resource families. Scroll horizontally to review every family.
          </caption>
          <thead>
            <tr>
              <th scope="col"><span className="heatmap-head matrix-corner">Target group</span></th>
              {RESOURCE_FAMILIES.map((family) => (
                <th scope="col" key={family.id} title={family.description}>
                  <span className="heatmap-head">
                    {plainCheckName(family.label)}
                    <small className="matrix-head-meta">
                      {family.metric} · {family.scoredForDdosReadiness ? 'DDoS readiness' : 'validation only'}
                    </small>
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map((group, groupIndex) => {
              const currentGroupId = String(group.id ?? '');
              return (
                <tr key={currentGroupId || `group-${groupIndex}`}>
                  <th scope="row">
                    <span className="heatmap-name">{String(group.name ?? group.id ?? 'Declared group')}</span>
                  </th>
                  {RESOURCE_FAMILIES.map((family) => {
                    const state = resourceFamilyVerdictState({
                      checkIds: applicableResourceFamilyCheckIds({
                        checks,
                        family,
                        groupId: currentGroupId,
                        targets: hydration.targets,
                        targetInventoryLoaded: true,
                      }),
                      groupId: currentGroupId,
                      runs: hydration.runs,
                      evidence,
                    });
                    return (
                      <td key={`${currentGroupId || groupIndex}-${family.id}`}>
                        <MatrixCell family={family} state={state} />
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <MatrixLegend />
      <p className="matrix-footnote">
        “Not run” or “Not validated” means no evidence-backed stored verdict was found in the bounded records currently loaded; it is not proof that no historical run exists.
      </p>
    </>
  );
}
