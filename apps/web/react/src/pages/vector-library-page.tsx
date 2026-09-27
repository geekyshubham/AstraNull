import { useEffect, useMemo, useState } from 'react';
import { BookOpenCheck, ChevronLeft, ChevronRight, Search, ShieldCheck, Target, TriangleAlert } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Select, type SelectOption } from '../components/ui/select';
import { DataTable, type TableColumn } from '../components/ui/table';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import { ConfirmModal, FormModal } from '../lib/crud-ui';
import { requestJson } from '../lib/api';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName } from '../lib/plain-language.mjs';
import { apiErrorMessage } from '../lib/error-messages';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import {
  evidenceCapabilityCopy,
  preferredRunnableCheck,
  searchAndFilterVectors,
  vectorTargetAvailability,
  type VectorAvailability,
} from '../lib/vector-library.mjs';
import { PageContextSummary, PageHeader } from './page-components';

const PAGE_SIZE = 25;
const API_PAGE_SIZE = 100;
const STYLE_ID = 'astranull-vector-library-styles';

const RUN_START_ROLES = new Set(['owner', 'admin', 'engineer']);
type Tone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function itemArray(value: unknown) {
  return Array.isArray(value) ? value as DataItem[] : [];
}

function strings(value: unknown) {
  return Array.isArray(value) ? value.map(String).filter(Boolean) : [];
}

function humanize(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

function targetLabel(target: DataItem) {
  const value = getString(target, ['value', 'hostname', 'id'], 'Unnamed target');
  const kind = humanize(getString(target, ['kind'], 'target'));
  return `${value} · ${kind}`;
}

let vectorLibraryRequestCache: { key: string; promise: Promise<DataItem[]> } | null = null;

function loadAllVectorPages(config: PortalConfig, session: Session, cacheKey: string) {
  if (vectorLibraryRequestCache?.key === cacheKey) return vectorLibraryRequestCache.promise;
  const promise = (async () => {
    const first = await requestJson(config, session, `/v1/vectors?limit=${API_PAGE_SIZE}&offset=0`) as DataItem;
    const firstItems = itemArray(first.items);
    const meta = first.meta && typeof first.meta === 'object' && !Array.isArray(first.meta) ? first.meta as DataItem : {};
    const total = Number(meta.total ?? firstItems.length);
    const offsets: number[] = [];
    for (let offset = API_PAGE_SIZE; offset < total; offset += API_PAGE_SIZE) offsets.push(offset);
    const rest = await Promise.all(offsets.map((offset) => requestJson(
      config,
      session,
      `/v1/vectors?limit=${API_PAGE_SIZE}&offset=${offset}`,
    ) as Promise<DataItem>));
    return [...firstItems, ...rest.flatMap((payload) => itemArray(payload.items))];
  })();
  vectorLibraryRequestCache = { key: cacheKey, promise };
  return promise;
}

function ensureStyles() {
  if (typeof document === 'undefined' || document.getElementById(STYLE_ID)) return;
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
.vector-library-page > .card { overflow: visible; }
.vector-library-controls { display: grid; grid-template-columns: minmax(220px, 1.4fr) repeat(3, minmax(160px, 1fr)); gap: var(--space-3); align-items: end; }
.vector-target-controls { display: grid; grid-template-columns: repeat(2, minmax(220px, 1fr)); gap: var(--space-3); }
.vector-search-control { display: flex; min-height: 44px; align-items: center; gap: var(--space-2); border: 1px solid var(--border); border-radius: var(--radius-pill); background: var(--surface-sunk); padding: 0 var(--space-3); }
.vector-search-control input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fg); }
.vector-library-table .data-table { min-width: 1120px; }
.vector-primary, .vector-cell-stack { display: flex; min-width: 0; flex-direction: column; gap: 4px; }
.vector-primary strong { color: var(--fg); }
.vector-primary small, .vector-cell-stack small { color: var(--fg-2); font-size: var(--text-xs); }
.vector-target-note { display: flex; gap: var(--space-3); align-items: flex-start; padding: var(--space-3); border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface-sunk); }
.vector-target-note svg { flex: none; margin-top: 2px; }
.vector-pagination { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); flex-wrap: wrap; }
.vector-pagination-actions { display: flex; gap: var(--space-2); }
.vector-detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
.vector-detail-block { padding: var(--space-3); border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface-sunk); }
.vector-detail-block.full { grid-column: 1 / -1; }
.vector-detail-block h4 { margin: 0 0 var(--space-2); color: var(--fg); font-size: var(--text-sm); }
.vector-detail-block p { margin: 0; color: var(--fg-2); line-height: 1.55; }
.vector-detail-actions { display: flex; justify-content: flex-end; gap: var(--space-2); flex-wrap: wrap; }
@media (max-width: 920px) { .vector-library-controls { grid-template-columns: repeat(2, minmax(0, 1fr)); } .vector-search-field { grid-column: 1 / -1; } }
@media (max-width: 620px) { .vector-library-controls, .vector-target-controls, .vector-detail-grid { grid-template-columns: minmax(0, 1fr); } .vector-search-field, .vector-detail-block.full { grid-column: auto; } }
`;
  document.head.appendChild(style);
}

const CAPABILITY_OPTIONS: SelectOption[] = [
  { value: '', label: 'All evidence capabilities' },
  { value: 'semantic_safe', label: 'E3 · Semantic-safe' },
  { value: 'declaration_only', label: 'E1 · Declaration only' },
  { value: 'transport_only', label: 'E2 · Transport only' },
  { value: 'soc_governed', label: 'E4 · SOC-governed' },
  { value: 'monitor_only', label: 'E5 · Monitor only' },
];

const EXECUTION_OPTIONS: SelectOption[] = [
  { value: '', label: 'All execution boundaries' },
  { value: 'safe_validation_available', label: 'Customer-safe mapping' },
  { value: 'soc_gated_only', label: 'SOC-gated only' },
  { value: 'monitor_only', label: 'Monitor only' },
];

const TARGET_AVAILABILITY_OPTIONS: SelectOption[] = [
  { value: '', label: 'All target dispositions' },
  { value: 'safe_runnable', label: 'Bounded check available' },
  { value: 'additional_input', label: 'Additional input required' },
  { value: 'target_not_supported', label: 'Target not supported' },
  { value: 'soc_gated', label: 'SOC-gated only' },
  { value: 'monitor_only', label: 'Monitor only' },
  { value: 'select_target', label: 'Awaiting target selection' },
];

export function VectorLibraryPage({
  data,
  config,
  session,
  onRefresh,
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [vectors, setVectors] = useState<DataItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [query, setQuery] = useState('');
  const [section, setSection] = useState('');
  const [capability, setCapability] = useState('');
  const [execution, setExecution] = useState('');
  const [targetAvailability, setTargetAvailability] = useState('');
  const [page, setPage] = useState(0);
  const [targetGroupId, setTargetGroupId] = useState('');
  const [targets, setTargets] = useState<DataItem[]>([]);
  const [targetsLoading, setTargetsLoading] = useState(false);
  const [targetsError, setTargetsError] = useState('');
  const [targetId, setTargetId] = useState('');
  const [selectedVector, setSelectedVector] = useState<DataItem | null>(null);
  const [selectedCheckId, setSelectedCheckId] = useState('');
  const [pendingRun, setPendingRun] = useState<{ vector: DataItem; check: DataItem; availability: VectorAvailability } | null>(null);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [targetReloadKey, setTargetReloadKey] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => ensureStyles(), []);
  const canStartBoundedRun = RUN_START_ROLES.has(String(session.role ?? '').trim().toLowerCase());

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError('');
    const cacheKey = `${session.tenant_id ?? ''}:${session.user_id ?? ''}:${reloadKey}`;
    loadAllVectorPages(config, session, cacheKey)
      .then((items) => { if (!cancelled) setVectors(items); })
      .catch((err) => {
        if (!cancelled) setLoadError(apiErrorMessage(err, 'Vector library could not be loaded.'));
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [config, session, reloadKey]);

  useEffect(() => {
    setTargets([]);
    setTargetId('');
    setTargetsError('');
    setTargetsLoading(false);
    if (!targetGroupId) return undefined;
    let cancelled = false;
    setTargetsLoading(true);
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(targetGroupId)}`)
      .then((payload) => {
        if (cancelled) return;
        const detail = payload as DataItem;
        setTargets(itemArray(detail.targets).filter((target) => target.deleted_at == null && target.archived_at == null));
      })
      .catch((err) => {
        if (!cancelled) setTargetsError(apiErrorMessage(err, 'Exact targets could not be loaded.'));
      })
      .finally(() => {
        if (!cancelled) setTargetsLoading(false);
      });
    return () => { cancelled = true; };
  }, [config, session, targetGroupId, targetReloadKey]);

  useEffect(() => {
    if (!targetGroupId) return;
    const stillActive = data.targetGroups.some((group) => (
      getString(group, ['id']) === targetGroupId
      && group.deleted_at == null
      && group.archived_at == null
    ));
    if (stillActive) return;
    setTargetGroupId('');
    setTargets([]);
    setTargetId('');
    setSelectedVector(null);
    setSelectedCheckId('');
    setPendingRun(null);
  }, [data.targetGroups, targetGroupId]);

  const activeGroups = data.targetGroups.filter((group) => group.deleted_at == null && group.archived_at == null);
  const selectedGroupActive = activeGroups.some((group) => getString(group, ['id']) === targetGroupId);
  const selectedTarget = selectedGroupActive
    ? targets.find((target) => getString(target, ['id']) === targetId) ?? null
    : null;
  const groupOptions: SelectOption[] = [
    { value: '', label: 'Select a declared target group' },
    ...activeGroups.map((group) => ({
      value: getString(group, ['id']),
      label: getString(group, ['name', 'title', 'id'], 'Unnamed group'),
    })),
  ];
  const targetOptions: SelectOption[] = [
    { value: '', label: targetsLoading ? 'Loading exact targets…' : 'Select an exact target' },
    ...targets.map((target) => ({ value: getString(target, ['id']), label: targetLabel(target) })),
  ];

  const filteredVectors = useMemo(() => searchAndFilterVectors(vectors, {
    query,
    section,
    capability,
    execution,
    targetAvailability,
    checks: data.checks,
    target: selectedTarget,
  }), [vectors, query, section, capability, execution, targetAvailability, data.checks, selectedTarget]);

  useEffect(() => setPage(0), [query, section, capability, execution, targetAvailability, targetId]);
  const pageCount = Math.max(1, Math.ceil(filteredVectors.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visibleVectors = filteredVectors.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const sectionOptions: SelectOption[] = [
    { value: '', label: 'All catalog sections' },
    ...[...new Set(vectors.map((vector) => getString(vector, ['section'])).filter(Boolean))]
      .sort()
      .map((value) => ({ value, label: value })),
  ];

  function openVector(vector: DataItem) {
    setSelectedVector(vector);
    setSelectedCheckId('');
    setError('');
  }

  async function refresh() {
    const refreshSelectedGroup = Boolean(targetGroupId);
    setBusy('refresh');
    setError('');
    setTargets([]);
    setTargetId('');
    setSelectedVector(null);
    setSelectedCheckId('');
    setPendingRun(null);
    try {
      await onRefresh();
      setReloadKey((value) => value + 1);
    } catch (err) {
      setError(apiErrorMessage(err, 'Vector library refresh failed.'));
    } finally {
      if (refreshSelectedGroup) setTargetReloadKey((value) => value + 1);
      setBusy('');
    }
  }

  function prepareRun() {
    if (!canStartBoundedRun) {
      setError('Your role can review vector evidence but cannot start validation runs.');
      return;
    }
    if (!selectedVector || !selectedTarget || !targetGroupId) return;
    const availability = vectorTargetAvailability(selectedVector, data.checks, selectedTarget);
    const check = availability.runnableChecks.find((candidate) => getString(candidate, ['check_id']) === selectedCheckId);
    if (!check) {
      setError('Select one mapped customer-safe check before continuing.');
      return;
    }
    setPendingRun({ vector: selectedVector, check, availability });
    setSelectedVector(null);
  }

  async function startRun() {
    if (!canStartBoundedRun) {
      setPendingRun(null);
      setError('Your role can review vector evidence but cannot start validation runs.');
      return;
    }
    if (!pendingRun || !selectedTarget || !targetGroupId) return;
    const checkId = getString(pendingRun.check, ['check_id']);
    setBusy('start-run');
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId },
      }) as DataItem;
      const run = result.run && typeof result.run === 'object' && !Array.isArray(result.run) ? result.run as DataItem : result;
      setMessage(`Bounded check started${getString(run, ['id']) ? `: ${getString(run, ['id'])}` : ''}. Evidence will be recorded at check level.`);
      setPendingRun(null);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Bounded check could not be started.'));
    } finally {
      setBusy('');
    }
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'vector',
      label: 'Vector',
      render: (vector) => (
        <span className="vector-primary">
          <strong>{plainCheckName(getString(vector, ['canonical_name'], 'Unnamed vector'))}</strong>
          <code className="traffic-path-label">{getString(vector, ['vector_id'], '—')}</code>
          <small>{getString(vector, ['family'])} · {getString(vector, ['protocol_service'])}</small>
        </span>
      ),
    },
    {
      key: 'exposure',
      label: 'Exposure evaluated',
      render: (vector) => <span className="vector-cell-stack"><strong>{getString(vector, ['targeted_resource_or_assumption'], 'Not recorded')}</strong><small>{getString(vector, ['intended_detection_goal'])}</small></span>,
    },
    {
      key: 'evidence',
      label: 'Evidence capability',
      render: (vector) => {
        const copy = evidenceCapabilityCopy(vector.evidence_capability);
        return <span className="vector-cell-stack"><Badge tone={copy.tone as Tone}>{getString(vector, ['evidence_tier'])} · {copy.label}</Badge><small>{copy.detail}</small></span>;
      },
    },
    {
      key: 'target',
      label: 'Selected-target disposition',
      render: (vector) => {
        const availability = vectorTargetAvailability(vector, data.checks, selectedTarget);
        return <span className="vector-cell-stack"><Badge tone={availability.tone as Tone}>{availability.label}</Badge><small>{availability.detail}</small></span>;
      },
    },
    {
      key: 'controls',
      label: 'Expected control',
      render: (vector) => <span className="vector-cell-stack"><strong>{getString(vector, ['expected_controls'], 'Not recorded')}</strong><small>Open to review failure meaning and evidence boundary.</small></span>,
    },
    {
      key: 'action',
      label: 'Action',
      render: (vector) => <Button size="sm" variant="secondary" onClick={() => openVector(vector)}>Review</Button>,
    },
  ];

  const detailAvailability = selectedVector ? vectorTargetAvailability(selectedVector, data.checks, selectedTarget) : null;
  const detailEvidence = selectedVector ? evidenceCapabilityCopy(selectedVector.evidence_capability) : null;
  const recommended = selectedVector && detailAvailability ? preferredRunnableCheck(selectedVector, detailAvailability) : null;
  const checkOptions: SelectOption[] = [
    { value: '', label: 'Select a mapped bounded check' },
    ...(detailAvailability?.runnableChecks ?? []).map((check) => ({
      value: getString(check, ['check_id']),
      label: `${getString(check, ['name', 'title', 'check_id'])}${recommended === check ? ' · semantic preference' : ''}`,
    })),
  ];

  return (
    <div className="content vector-library-page">
      <PageHeader
        route="checks"
        eyebrow="721-vector catalog"
        title="Vector library"
        description="Understand the exposure each vector evaluates, what failure means, which control should prevent it, and whether an exact declared target is eligible for a bounded check."
        actions={<Button variant="secondary" size="sm" loading={busy === 'refresh'} disabled={busy !== ''} onClick={() => void refresh()}>Refresh</Button>}
      />
      <PageContextSummary>
        <span className="tabular-nums">{vectors.length || 721}</span> catalog vectors · bounded checks only · SOC/high-scale vectors remain request-only
      </PageContextSummary>
      {message ? <div className="form-banner success" role="status" aria-live="polite">{message}</div> : null}
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}

      <Card>
        <CardHeader>
          <div><CardTitle>Evaluation target</CardTitle><CardDescription>Select both identifiers explicitly. AstraNull never substitutes the first group or target.</CardDescription></div>
          <Badge tone={selectedTarget ? 'success' : 'warn'}>{selectedTarget ? 'Exact target selected' : 'Selection required'}</Badge>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="vector-target-controls">
            <Select label="Declared target group" value={targetGroupId} options={groupOptions} onChange={setTargetGroupId} />
            <Select label="Exact target" value={targetId} options={targetOptions} disabled={!targetGroupId || targetsLoading || Boolean(targetsError)} onChange={setTargetId} />
          </div>
          {targetsError ? <div className="form-banner error" role="alert">{targetsError}</div> : null}
          <div className="vector-target-note" role="note">
            <Target size={18} aria-hidden="true" />
            <div><strong>{selectedTarget ? targetLabel(selectedTarget) : 'No exact target selected'}</strong><p className="muted">Target fit is recalculated from each mapped check. Ownership, eligibility, concurrency, and rate limits are checked again at launch.</p></div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div><CardTitle>Catalog</CardTitle><CardDescription>{filteredVectors.length} matching vectors. Only {PAGE_SIZE} rows render per page.</CardDescription></div>
          <Badge tone="muted">No vector-level verdict synthesis</Badge>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="vector-library-controls" role="group" aria-label="Vector library filters">
            <label className="field vector-search-field"><span>Search</span><span className="vector-search-control"><Search size={15} aria-hidden="true" /><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="ID, name, protocol, exposure, control…" /></span></label>
            <Select label="Catalog section" value={section} options={sectionOptions} onChange={setSection} />
            <Select label="Evidence capability" value={capability} options={CAPABILITY_OPTIONS} onChange={setCapability} />
            <Select label="Execution boundary" value={execution} options={EXECUTION_OPTIONS} onChange={setExecution} />
            <Select label="Selected-target disposition" value={targetAvailability} options={TARGET_AVAILABILITY_OPTIONS} onChange={setTargetAvailability} />
          </div>
          {loading ? <PortalLoadingSkeleton rows={6} label="Loading vector library" /> : (
            <DataTable
              className="vector-library-table"
              columns={columns}
              items={visibleVectors}
              getRowId={(vector) => getString(vector, ['vector_id'])}
              loadError={loadError}
              onRetry={() => setReloadKey((value) => value + 1)}
              empty={<EmptyState icon={BookOpenCheck} title="No vectors match these filters" body="Adjust the search, evidence, execution, or selected-target disposition filters." />}
            />
          )}
          {!loading && filteredVectors.length > 0 ? (
            <nav className="vector-pagination" aria-label="Vector library pages">
              <span className="muted">Page {safePage + 1} of {pageCount} · rows {safePage * PAGE_SIZE + 1}–{Math.min((safePage + 1) * PAGE_SIZE, filteredVectors.length)} of {filteredVectors.length}</span>
              <span className="vector-pagination-actions">
                <Button size="sm" variant="secondary" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}><ChevronLeft size={15} aria-hidden="true" /> Previous</Button>
                <Button size="sm" variant="secondary" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next <ChevronRight size={15} aria-hidden="true" /></Button>
              </span>
            </nav>
          ) : null}
        </CardContent>
      </Card>

      <FormModal
        open={Boolean(selectedVector)}
        title={selectedVector ? `${getString(selectedVector, ['vector_id'])} · ${plainCheckName(getString(selectedVector, ['canonical_name']))}` : 'Vector detail'}
        description={selectedVector ? `${getString(selectedVector, ['section'])} · ${getString(selectedVector, ['family'])}` : undefined}
        onClose={() => setSelectedVector(null)}
        wide
      >
        {selectedVector && detailAvailability && detailEvidence ? (
          <div className="stack-tight">
            <div className="vector-detail-grid">
              <section className="vector-detail-block"><h4>Intended detection goal</h4><p>{getString(selectedVector, ['intended_detection_goal'])}</p></section>
              <section className="vector-detail-block"><h4>What failure means</h4><p>{getString(selectedVector, ['failure_means'])}</p></section>
              <section className="vector-detail-block"><h4>Control that should prevent it</h4><p>{getString(selectedVector, ['expected_controls'])}</p></section>
              <section className="vector-detail-block"><h4>Evidence boundary</h4><p><Badge tone={detailEvidence.tone as Tone}>{getString(selectedVector, ['evidence_tier'])} · {detailEvidence.label}</Badge></p><p>{detailEvidence.detail}</p></section>
              <section className="vector-detail-block full"><h4>How the exposure works</h4><p>{getString(selectedVector, ['how_it_works'])}</p></section>
              <section className="vector-detail-block"><h4>Defensive indicators</h4><p>{getString(selectedVector, ['defensive_indicators'])}</p></section>
              <section className="vector-detail-block"><h4>Scope boundary</h4><p>{getString(selectedVector, ['boundaries', 'out_of_scope_reason'], 'No additional boundary recorded.')}</p></section>
            </div>
            <div className="vector-target-note" role="note">
              {detailAvailability.id === 'safe_runnable' ? <ShieldCheck size={18} aria-hidden="true" /> : <TriangleAlert size={18} aria-hidden="true" />}
              <div><Badge tone={detailAvailability.tone as Tone}>{detailAvailability.label}</Badge><p className="muted">{detailAvailability.detail}</p></div>
            </div>
            {detailAvailability.id === 'safe_runnable' && canStartBoundedRun ? <Select label="Mapped bounded check" value={selectedCheckId} options={checkOptions} onChange={setSelectedCheckId} /> : null}
            {detailAvailability.id === 'safe_runnable' && !canStartBoundedRun ? <div className="form-banner neutral" role="note">Your role can review this vector and its target applicability, but only owners, admins, and engineers can start bounded checks.</div> : null}
            <div className="vector-detail-actions">
              {detailAvailability.id === 'soc_gated' ? <AnchorButton href="#runs" variant="secondary" size="sm">Open governed request workflow</AnchorButton> : null}
              {detailAvailability.id === 'monitor_only' ? <AnchorButton href="#integrations" variant="secondary" size="sm">Open telemetry integrations</AnchorButton> : null}
              <Button variant="ghost" size="sm" onClick={() => setSelectedVector(null)}>Close</Button>
              {detailAvailability.id === 'safe_runnable' && canStartBoundedRun ? <Button size="sm" disabled={!selectedCheckId || busy !== ''} onClick={prepareRun}>Review run</Button> : null}
            </div>
          </div>
        ) : null}
      </FormModal>

      <ConfirmModal
        open={Boolean(pendingRun)}
        title="Start this bounded check?"
        description={pendingRun && selectedTarget ? (
          <div className="stack-tight">
            <p><strong>Vector intent:</strong> {getString(pendingRun.vector, ['vector_id'])} · {plainCheckName(getString(pendingRun.vector, ['canonical_name']))}</p>
            <p><strong>Target group:</strong> {targetGroupId}</p>
            <p><strong>Exact target:</strong> {targetLabel(selectedTarget)} · {targetId}</p>
            <p><strong>Check:</strong> {getString(pendingRun.check, ['name', 'title', 'check_id'])} · {getString(pendingRun.check, ['check_id'])}</p>
            <p><strong>Evidence limit:</strong> {evidenceCapabilityCopy(pendingRun.vector.evidence_capability).detail}</p>
          </div>
        ) : ''}
        confirmLabel="Start bounded check"
        confirmTone="default"
        busy={busy === 'start-run'}
        onCancel={() => setPendingRun(null)}
        onConfirm={() => void startRun()}
      />
    </div>
  );
}
