import { ShieldCheck, TriangleAlert } from 'lucide-react';
import type { CSSProperties } from 'react';
import { useEffect, useId, useMemo, useState } from 'react';
import { requestJson } from '../../lib/api';
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

const STATUS_LABEL: Record<ResourceMatrixStatus, string> = {
  protected: 'Protected',
  exposed: 'Exposed',
  inconclusive: 'Inconclusive',
  stale: 'Stale',
  not_run: 'Not run',
  not_applicable: 'Not applicable',
};

const CELL_STYLE: Record<ResourceMatrixStatus, CSSProperties> = {
  protected: {
    background: 'color-mix(in oklab, var(--success), transparent 90%)',
    color: 'var(--success)',
  },
  exposed: {
    background: 'color-mix(in oklab, var(--danger), transparent 91%)',
    color: 'var(--danger)',
  },
  inconclusive: {
    background: 'color-mix(in oklab, var(--warn), transparent 90%)',
    color: 'var(--warn)',
  },
  stale: {
    border: '1px dashed var(--warn)',
    background: 'color-mix(in oklab, var(--warn), transparent 94%)',
    color: 'var(--warn)',
  },
  not_run: {
    border: '1px solid var(--border)',
    background: 'color-mix(in oklab, var(--fg), transparent 96%)',
    color: 'var(--fg-2)',
  },
  not_applicable: {
    border: '1px solid var(--border)',
    background: 'color-mix(in oklab, var(--fg), transparent 94%)',
    color: 'var(--fg-2)',
  },
};

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
  if (state.status === 'not_applicable') {
    return `${family.label}: no mapped checks support this target group's declared target kinds.`;
  }
  if (state.status === 'not_run') {
    return `${family.label}: no stored verdict found in the loaded API window for ${state.applicableCheckCount} applicable checks.`;
  }
  return `${family.label} (${family.metric}): ${STATUS_LABEL[state.status]}. ${state.testedCheckCount} of ${state.applicableCheckCount} applicable checks tested; ${state.freshCheckCount} fresh and ${state.staleCheckCount} stale. ${latestLabel(state.latestEvidenceAt)}.`;
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
      className={`heatmap-cell heatmap-${STATUS_TONE[state.status]}`}
      style={{ ...CELL_STYLE[state.status], display: 'block', minWidth: '8.5rem', textAlign: 'center' }}
      title={description}
      aria-label={description}
    >
      <strong style={{ display: 'block' }}>{STATUS_LABEL[state.status]}</strong>
      <small style={{ display: 'block', marginTop: '0.2rem', color: 'inherit' }}>{count}</small>
    </span>
  );
}

function MatrixLegend() {
  return (
    <div className="heatmap-legend" aria-label="Matrix status legend">
      <Badge tone="success">Protected</Badge>
      <Badge tone="danger">Exposed</Badge>
      <Badge tone="warn">Inconclusive</Badge>
      <Badge tone="warn">Stale</Badge>
      <Badge tone="muted">Not run</Badge>
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
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Loading verdict evidence…"
        body="Loading declared targets and stored verdict details before calculating posture."
        variant="skeleton"
      />
    );
  }

  return (
    <>
      <p id={descriptionId} className="muted" style={{ marginTop: 0 }}>
        Each cell uses the latest evidence-referenced stored verdict per applicable check. Evidence is fresh for {RESOURCE_EVIDENCE_FRESHNESS_DAYS} days.
        Protected requires fresh pass evidence for every applicable check; partial coverage remains inconclusive.
      </p>
      <div
        className="heatmap"
        role="region"
        aria-label={`Resource-exhaustion verdict matrix for ${groups.length} target groups`}
        aria-describedby={descriptionId}
        tabIndex={0}
      >
        <table style={{ borderCollapse: 'separate', borderSpacing: '0.4rem', minWidth: '100%', width: 'max-content' }}>
          <caption style={{ textAlign: 'left', padding: '0 0.4rem 0.4rem', color: 'var(--fg-2)' }}>
            All {groups.length} active target groups. Scroll horizontally to review every resource family.
          </caption>
          <thead>
            <tr>
              <th className="heatmap-head" scope="col" style={{ textAlign: 'left', minWidth: '10rem' }}>Target group</th>
              {RESOURCE_FAMILIES.map((family) => (
                <th className="heatmap-head" scope="col" key={family.id} title={`Primary metric: ${family.metric}`}>
                  {family.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map((group, groupIndex) => {
              const currentGroupId = String(group.id ?? '');
              return (
                <tr key={currentGroupId || `group-${groupIndex}`}>
                  <th className="heatmap-name" scope="row" style={{ textAlign: 'left' }}>
                    {String(group.name ?? group.id ?? 'Declared group')}
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
      <p className="muted" style={{ marginBottom: 0 }}>
        “Not run” means no evidence-backed stored verdict was found in the bounded records returned by the API; it is not proof that no historical run exists.
      </p>
    </>
  );
}
