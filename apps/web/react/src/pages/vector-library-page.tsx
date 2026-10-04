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
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../lib/route-params';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName } from '../lib/plain-language.mjs';
import { apiErrorMessage } from '../lib/error-messages';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatNumber } from '../lib/utils';
import {
  evidenceCapabilityCopy,
  preferredRunnableCheck,
  searchAndFilterVectors,
  vectorTargetAvailability,
  type VectorAvailability,
} from '../lib/vector-library.mjs';
import { PageContextSummary, PageHeader } from './page-components';
import './vector-library-page.css';

const PAGE_SIZE = 25;
const API_PAGE_SIZE = 100;

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
  promise.catch(() => {
    if (vectorLibraryRequestCache?.promise === promise) vectorLibraryRequestCache = null;
  });
  return promise;
}

const CAPABILITY_OPTIONS: SelectOption[] = [
  { value: '', label: 'Any evidence level' },
  { value: 'semantic_safe', label: 'Semantic-safe (E3)' },
  { value: 'declaration_only', label: 'Declaration only (E1)' },
  { value: 'transport_only', label: 'Transport only (E2)' },
  { value: 'soc_governed', label: 'SOC-governed (E4)' },
  { value: 'monitor_only', label: 'Monitor only (E5)' },
];

const EXECUTION_OPTIONS: SelectOption[] = [
  { value: '', label: 'Any execution boundary' },
  { value: 'safe_validation_available', label: 'Has a customer-safe check' },
  { value: 'monitor_only', label: 'Monitor only' },
];

const TARGET_AVAILABILITY_OPTIONS: SelectOption[] = [
  { value: '', label: 'Any fit' },
  { value: 'safe_runnable', label: 'Bounded check available' },
  { value: 'additional_input', label: 'Additional input required' },
  { value: 'target_not_supported', label: 'Target kind not supported' },
  { value: 'monitor_only', label: 'Monitor only' },
];

function readInitialPage() {
  const value = Number(getRouteParam('page'));
  return Number.isInteger(value) && value > 1 ? value - 1 : 0;
}

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
  const [query, setQuery] = useState(() => getRouteParam('q'));
  const [section, setSection] = useState('');
  const [capability, setCapability] = useState('');
  const [execution, setExecution] = useState('');
  const [targetAvailability, setTargetAvailability] = useState('');
  const [page, setPage] = useState(readInitialPage);
  const [targets, setTargets] = useState<DataItem[]>([]);
  const [targetsStatus, setTargetsStatus] = useState<'loading' | 'loaded' | 'error'>('loading');
  const [targetsError, setTargetsError] = useState('');
  const [targetId, setTargetId] = useState(() => getRouteParam('target'));
  const [targetQuery, setTargetQuery] = useState('');
  const [selectedVector, setSelectedVector] = useState<DataItem | null>(null);
  const [selectedCheckId, setSelectedCheckId] = useState('');
  const [pendingRun, setPendingRun] = useState<{ vector: DataItem; check: DataItem; availability: VectorAvailability } | null>(null);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState<{ text: string; targetId: string } | null>(null);
  const [error, setError] = useState('');
  const [targetReloadKey, setTargetReloadKey] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);

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

  // Target-first: one declared-target list; each target's group is resolved from its own record.
  useEffect(() => {
    let cancelled = false;
    setTargetsStatus('loading');
    setTargetsError('');
    requestJson(config, session, '/v1/targets')
      .then((payload) => {
        if (cancelled) return;
        const items = itemArray((payload as DataItem)?.items).filter((target) => target.deleted_at == null && target.archived_at == null);
        setTargets(items);
        setTargetsStatus('loaded');
      })
      .catch((err) => {
        if (cancelled) return;
        setTargetsError(apiErrorMessage(err, 'Declared targets could not be loaded.'));
        setTargetsStatus('error');
      });
    return () => { cancelled = true; };
  }, [config, session, targetReloadKey]);

  useEffect(() => {
    replaceRouteParams({ target: targetId || null, q: query.trim() || null, page: page > 0 ? String(page + 1) : null });
  }, [targetId, query, page]);

  const selectedTarget = targets.find((target) => getString(target, ['id']) === targetId) ?? null;
  const targetGroupId = getString(selectedTarget, ['target_group_id']);
  const targetGroupName = getString(
    data.targetGroups.find((group) => getString(group, ['id']) === targetGroupId) ?? null,
    ['name'],
    getString(selectedTarget, ['target_group_name'], targetGroupId)
  );
  const missingDeepLinkTarget = Boolean(targetId) && targetsStatus === 'loaded' && !selectedTarget;
  const targetQueryText = targetQuery.trim().toLowerCase();
  const matchingTargets = targetQueryText
    ? targets.filter((target) => `${targetLabel(target)} ${getString(target, ['target_group_name'])} ${getString(target, ['id'])}`.toLowerCase().includes(targetQueryText))
    : targets;
  const targetOptions: SelectOption[] = [
    { value: '', label: targetsStatus === 'loading' ? 'Loading declared targets…' : 'No target (browse the catalog)' },
    ...(selectedTarget && !matchingTargets.includes(selectedTarget) ? [selectedTarget] : []).concat(matchingTargets).slice(0, 200).map((target) => ({
      value: getString(target, ['id']),
      label: targetLabel(target),
      description: getString(target, ['target_group_name']) ? `in ${getString(target, ['target_group_name'])}` : undefined,
    })),
  ];

  const runnableChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'safe');
  const [serverFit, setServerFit] = useState<{ targetId: string; status: 'loading' | 'loaded' | 'error'; checks: DataItem[] }>({ targetId: '', status: 'loading', checks: [] });
  const fitTargetId = selectedTarget ? getString(selectedTarget, ['id']) : '';
  useEffect(() => {
    if (!fitTargetId) return undefined;
    const id = fitTargetId;
    let cancelled = false;
    setServerFit({ targetId: id, status: 'loading', checks: [] });
    requestJson(config, session, `/v1/targets/${encodeURIComponent(id)}/compatible-checks`)
      .then((payload) => {
        if (!cancelled) setServerFit({ targetId: id, status: 'loaded', checks: itemArray((payload as DataItem)?.checks) });
      })
      .catch(() => {
        if (!cancelled) setServerFit({ targetId: id, status: 'error', checks: [] });
      });
    return () => { cancelled = true; };
  }, [config, session, fitTargetId]);
  const fitForSelected = fitTargetId && serverFit.targetId === fitTargetId ? serverFit : null;
  const compatibleRunnable = fitForSelected?.status === 'loaded'
    ? fitForSelected.checks.filter((check) => getString(check, ['safety_class']) === 'safe')
    : [];

  const filteredVectors = useMemo(() => searchAndFilterVectors(vectors, {
    query,
    section,
    capability,
    execution,
    targetAvailability,
    checks: data.checks,
    target: selectedTarget,
  }), [vectors, query, section, capability, execution, targetAvailability, data.checks, selectedTarget]);

  const [filterSignature, setFilterSignature] = useState(`${section}|${capability}|${execution}|${targetAvailability}`);
  useEffect(() => {
    const signature = `${section}|${capability}|${execution}|${targetAvailability}`;
    if (signature !== filterSignature) {
      setFilterSignature(signature);
      setPage(0);
    }
  }, [section, capability, execution, targetAvailability, filterSignature]);
  const pageCount = Math.max(1, Math.ceil(filteredVectors.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visibleVectors = filteredVectors.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const sectionOptions: SelectOption[] = [
    { value: '', label: 'All catalog sections' },
    ...[...new Set(vectors.map((vector) => getString(vector, ['section'])).filter(Boolean))]
      .sort()
      .map((value) => ({ value, label: value })),
  ];
  const activeFilters = [
    section ? `Section: ${section}` : '',
    capability ? `Evidence: ${CAPABILITY_OPTIONS.find((option) => option.value === capability)?.label ?? capability}` : '',
    execution ? `Execution: ${EXECUTION_OPTIONS.find((option) => option.value === execution)?.label ?? execution}` : '',
    targetAvailability ? `Fit: ${TARGET_AVAILABILITY_OPTIONS.find((option) => option.value === targetAvailability)?.label ?? targetAvailability}` : '',
    query.trim() ? `Search: “${query.trim()}”` : '',
  ].filter(Boolean);

  function clearFilters() {
    setQuery('');
    setSection('');
    setCapability('');
    setExecution('');
    setTargetAvailability('');
    setPage(0);
  }

  function chooseTarget(next: string) {
    setTargetId(next);
    setPage(0);
    setPendingRun(null);
    setSelectedCheckId('');
    setMessage(null);
  }

  function openVector(vector: DataItem) {
    setSelectedVector(vector);
    setSelectedCheckId('');
    setError('');
  }

  async function refresh() {
    setBusy('refresh');
    setError('');
    setSelectedVector(null);
    setSelectedCheckId('');
    setPendingRun(null);
    try {
      await onRefresh();
      setReloadKey((value) => value + 1);
      setTargetReloadKey((value) => value + 1);
    } catch (err) {
      setError(apiErrorMessage(err, 'Vector library refresh failed.'));
    } finally {
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
    setMessage(null);
    try {
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId },
      });
      setMessage({
        text: `Bounded check ${plainCheckName(getString(pendingRun.check, ['name', 'check_id']))} started on ${getString(selectedTarget, ['value'], targetId)}. Its result and evidence are recorded on the target.`,
        targetId,
      });
      setPendingRun(null);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Bounded check could not be started. Nothing was sent.'));
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
          <code className="traffic-path-label">{getString(vector, ['vector_id'], 'No ID')}</code>
          <small>{getString(vector, ['family'])} · {getString(vector, ['protocol_service'])}</small>
        </span>
      ),
    },
    {
      key: 'target',
      label: selectedTarget ? `Fit for ${getString(selectedTarget, ['value'], 'target')}` : 'Fit for target',
      render: (vector) => {
        if (!selectedTarget) return <span className="muted small">Choose a target to see fit</span>;
        const availability = vectorTargetAvailability(vector, data.checks, selectedTarget);
        return <span className="vector-cell-stack"><Badge tone={availability.tone as Tone}>{availability.label}</Badge><small>{availability.detail}</small></span>;
      },
    },
    {
      key: 'evidence',
      label: 'Evidence level',
      render: (vector) => {
        const copy = evidenceCapabilityCopy(vector.evidence_capability);
        return <span className="vector-cell-stack"><Badge tone={copy.tone as Tone}>{copy.label}</Badge><small>{getString(vector, ['evidence_tier'])} · {copy.detail}</small></span>;
      },
    },
    {
      key: 'exposure',
      label: 'What it evaluates',
      render: (vector) => <span className="vector-cell-stack"><strong>{getString(vector, ['targeted_resource_or_assumption'], 'Not recorded')}</strong><small>{getString(vector, ['intended_detection_goal'])}</small></span>,
    },
    {
      key: 'action',
      label: 'Action',
      render: (vector) => <Button size="sm" variant="secondary" onClick={() => openVector(vector)} aria-label={`Review ${getString(vector, ['vector_id'])}`}>Review</Button>,
    },
  ];

  const detailAvailability = selectedVector ? vectorTargetAvailability(selectedVector, data.checks, selectedTarget) : null;
  const detailEvidence = selectedVector ? evidenceCapabilityCopy(selectedVector.evidence_capability) : null;
  const recommended = selectedVector && detailAvailability ? preferredRunnableCheck(selectedVector, detailAvailability) : null;
  const mappedCheckIds = selectedVector ? [...new Set([
    ...(Array.isArray(selectedVector.semantic_safe_check_ids) ? selectedVector.semantic_safe_check_ids : []),
    ...(Array.isArray(selectedVector.mapped_check_ids) ? selectedVector.mapped_check_ids : []),
    ...(detailAvailability?.runnableChecks ?? []).map((check) => getString(check, ['check_id'])),
  ].map(String).filter(Boolean))] : [];
  const checkOptions: SelectOption[] = [
    { value: '', label: 'Select a mapped bounded check' },
    ...(detailAvailability?.runnableChecks ?? []).map((check) => ({
      value: getString(check, ['check_id']),
      label: `${plainCheckName(getString(check, ['name', 'title', 'check_id']))}${recommended === check ? ' (semantic match)' : ''}`,
    })),
  ];
  const checkHref = (checkId: string) => `${buildDetailHref('check-detail', checkId)}${selectedTarget ? `&target=${encodeURIComponent(targetId)}` : ''}`;

  return (
    <div className="content vector-library-page">
      <PageHeader
        route="checks"
        eyebrow="Checks and catalog"
        title="Check library"
        description="Choose a declared target, see which bounded checks fit it and what their evidence can and cannot prove. The vector catalog explains each exposure; only mapped checks run."
        actions={<Button variant="secondary" size="sm" loading={busy === 'refresh'} disabled={busy !== ''} onClick={() => void refresh()}>Refresh</Button>}
      />
      <dl className="vector-facts" aria-label="Catalog and check counts">
        <div>
          <dt>Catalog vectors</dt>
          <dd className="tabular-nums">{loading ? 'Loading' : loadError ? 'Unavailable' : formatNumber(vectors.length)}</dd>
          <dd className="vector-fact-hint">Exposures described; not checks run</dd>
        </div>
        <div>
          <dt>Runnable checks</dt>
          <dd className="tabular-nums">{data.loadErrors.checks ? 'Unavailable' : formatNumber(runnableChecks.length)}</dd>
          <dd className="vector-fact-hint">Customer-safe bounded checks in the catalog</dd>
        </div>
        <div>
          <dt>Fit this target</dt>
          <dd className="tabular-nums">{!selectedTarget ? 'No target' : !fitForSelected || fitForSelected.status === 'loading' ? 'Checking' : fitForSelected.status === 'error' ? 'Unavailable' : formatNumber(compatibleRunnable.length)}</dd>
          <dd className="vector-fact-hint">{selectedTarget ? `Runnable checks supporting ${humanize(getString(selectedTarget, ['kind'], 'this kind'))}` : 'Choose a target below'}</dd>
        </div>
        <div>
          <dt>Launch access</dt>
          <dd>{canStartBoundedRun ? 'Can start checks' : 'Review only'}</dd>
          <dd className="vector-fact-hint">Ownership and rate gates still apply</dd>
        </div>
      </dl>
      <PageContextSummary>
        Catalog vectors, runnable checks, and checks that fit a target are different counts. No vector receives a verdict on its own.
      </PageContextSummary>
      {message ? (
        <div className="form-banner success row-actions" role="status" aria-live="polite">
          <span>{message.text}</span>
          {message.targetId ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-detail', message.targetId)}>Open target</AnchorButton> : null}
        </div>
      ) : null}
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}

      <Card className="vector-scope-card">
        <CardHeader>
          <div><CardTitle>Target</CardTitle><CardDescription>Pick the exact declared target. Its group is taken from the target record; nothing is chosen for you.</CardDescription></div>
          <Badge tone={selectedTarget ? 'success' : 'muted'}>{selectedTarget ? 'Target selected' : 'Browsing'}</Badge>
        </CardHeader>
        <CardContent className="vector-scope-body">
          <div className="vector-target-controls">
            <label className="field">
              <span>Find target</span>
              <input
                type="search"
                value={targetQuery}
                onChange={(event) => setTargetQuery(event.target.value)}
                placeholder="Hostname, URL, IP, or group"
                autoComplete="off"
                disabled={targetsStatus !== 'loaded'}
              />
            </label>
            <Select
              label="Target"
              value={selectedTarget ? targetId : ''}
              options={targetOptions}
              disabled={targetsStatus !== 'loaded' || targets.length === 0}
              onChange={chooseTarget}
              hint={targetsStatus === 'loaded' ? `${formatNumber(matchingTargets.length)} of ${formatNumber(targets.length)} declared targets${matchingTargets.length > 200 ? ', first 200 listed' : ''}` : undefined}
            />
          </div>
          {targetsStatus === 'error' ? (
            <div className="form-banner error row-actions" role="alert">
              <span>{targetsError} The catalog stays browsable without target fit.</span>
              <Button size="sm" variant="secondary" onClick={() => setTargetReloadKey((value) => value + 1)}>Retry</Button>
            </div>
          ) : null}
          {missingDeepLinkTarget ? (
            <div className="form-banner neutral row-actions" role="status">
              <span>Target {targetId} from the link is not visible in this workspace. No other target was substituted.</span>
              <Button size="sm" variant="secondary" onClick={() => chooseTarget('')}>Clear target</Button>
            </div>
          ) : null}
          {targetsStatus === 'loaded' && targets.length === 0 ? (
            <div className="form-banner neutral row-actions" role="status">
              <span>No declared targets yet. Browse the catalog, or declare a target to see which checks fit it.</span>
              <AnchorButton size="sm" variant="secondary" href="#targets">Open targets</AnchorButton>
            </div>
          ) : null}
          <div className="vector-target-note" role="note">
            <Target size={18} aria-hidden="true" />
            <div>
              <strong>{selectedTarget ? targetLabel(selectedTarget) : 'Browsing without a target'}</strong>
              <p className="muted">
                {selectedTarget
                  ? <>In {targetGroupName || 'an unrecorded group'}. Fit comes from each mapped check's supported target kinds. <a href={buildDetailHref('target-detail', targetId)}>Open target</a></>
                  : 'Without a target the catalog shows purpose and evidence limits only.'}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="vector-catalog-card">
        <CardHeader>
          <div>
            <CardTitle>Vector catalog</CardTitle>
            <CardDescription>
              {loading ? 'Loading catalog…' : `${formatNumber(filteredVectors.length)} of ${formatNumber(vectors.length)} vectors match.`}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="vector-catalog-body">
          <div className="vector-library-controls" role="group" aria-label="Vector library filters">
            <label className="field vector-search-field"><span>Search</span><span className="vector-search-control"><Search size={15} aria-hidden="true" /><input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} placeholder="Name, ID, protocol, exposure, control" aria-label="Search the vector catalog" /></span></label>
            <Select label="Fit for target" value={targetAvailability} options={TARGET_AVAILABILITY_OPTIONS} onChange={setTargetAvailability} disabled={!selectedTarget} hint={selectedTarget ? undefined : 'Choose a target first'} />
          </div>
          <div className="vector-filter-summary">
            <Button size="sm" variant="ghost" aria-expanded={showAdvanced} aria-controls="vector-advanced-filters" onClick={() => setShowAdvanced((open) => !open)}>
              {showAdvanced ? 'Hide more filters' : 'More filters'}
            </Button>
            {activeFilters.length ? (
              <>
                <span className="muted small" aria-live="polite">{activeFilters.join(' · ')}</span>
                <Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button>
              </>
            ) : null}
          </div>
          {showAdvanced ? (
            <div className="vector-library-controls vector-advanced-filters" id="vector-advanced-filters" role="group" aria-label="More vector filters">
              <Select label="Catalog section" value={section} options={sectionOptions} onChange={setSection} />
              <Select label="Evidence level" value={capability} options={CAPABILITY_OPTIONS} onChange={setCapability} />
              <Select label="Execution boundary" value={execution} options={EXECUTION_OPTIONS} onChange={setExecution} />
            </div>
          ) : null}
          {loading ? <PortalLoadingSkeleton rows={6} label="Loading vector library" /> : (
            <DataTable
              className="vector-library-table"
              columns={columns}
              items={visibleVectors}
              getRowId={(vector) => getString(vector, ['vector_id'])}
              loadError={loadError}
              onRetry={() => setReloadKey((value) => value + 1)}
              empty={vectors.length > 0
                ? <EmptyState icon={BookOpenCheck} title="No vectors match these filters." body={activeFilters.join(' · ') || 'Adjust the search or filters.'} actionLabel="Clear filters" onAction={clearFilters} />
                : <EmptyState icon={BookOpenCheck} title="The vector catalog is empty." body="No catalog entries were returned for this workspace." />}
            />
          )}
          {!loading && filteredVectors.length > 0 ? (
            <nav className="vector-pagination" aria-label="Vector catalog pages">
              <span className="muted">Page {safePage + 1} of {pageCount} · rows {safePage * PAGE_SIZE + 1}-{Math.min((safePage + 1) * PAGE_SIZE, filteredVectors.length)} of {filteredVectors.length}</span>
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
        title={selectedVector ? plainCheckName(getString(selectedVector, ['canonical_name'], getString(selectedVector, ['vector_id']))) : 'Vector detail'}
        description={selectedVector ? `${getString(selectedVector, ['vector_id'])} · ${getString(selectedVector, ['section'])} · ${getString(selectedVector, ['family'])}` : undefined}
        onClose={() => setSelectedVector(null)}
        wide
      >
        {selectedVector && detailAvailability && detailEvidence ? (
          <div className="vector-detail">
            <div className="vector-detail-grid">
              <section className="vector-detail-block"><h4>What it checks</h4><p>{getString(selectedVector, ['intended_detection_goal'], 'Not recorded')}</p></section>
              <section className="vector-detail-block"><h4>Why it matters</h4><p>{getString(selectedVector, ['failure_means'], 'Not recorded')}</p></section>
              <section className="vector-detail-block"><h4>Expected protection</h4><p>{getString(selectedVector, ['expected_controls'], 'Not recorded')}</p></section>
              <section className="vector-detail-block"><h4>Evidence limits</h4><p><Badge tone={detailEvidence.tone as Tone}>{detailEvidence.label}</Badge></p><p>{detailEvidence.detail}</p></section>
              <section className="vector-detail-block full"><h4>How the exposure works</h4><p>{getString(selectedVector, ['how_it_works'], 'Not recorded')}</p></section>
              <section className="vector-detail-block"><h4>Defensive indicators</h4><p>{getString(selectedVector, ['defensive_indicators'], 'Not recorded')}</p></section>
              <section className="vector-detail-block"><h4>Scope boundary</h4><p>{getString(selectedVector, ['boundaries', 'out_of_scope_reason'], 'No additional boundary recorded.')}</p></section>
              <section className="vector-detail-block full">
                <h4>Mapped checks</h4>
                {mappedCheckIds.length ? (
                  <ul className="vector-mapped-checks">
                    {mappedCheckIds.map((checkId) => {
                      const check = data.checks.find((candidate) => getString(candidate, ['check_id']) === checkId);
                      return (
                        <li key={checkId}>
                          {check ? <a href={checkHref(checkId)}>{plainCheckName(getString(check, ['name'], checkId))}</a> : <span>{checkId}</span>}
                          <code className="traffic-path-label">{checkId}</code>
                          {!check ? <span className="muted small"> not in the current catalog</span> : null}
                        </li>
                      );
                    })}
                  </ul>
                ) : <p>No bounded check is mapped. This vector is explanatory only.</p>}
              </section>
            </div>
            <div className="vector-detail-rail" role="group" aria-label="Target fit and launch">
              <div className="vector-target-note" role="note">
                {detailAvailability.id === 'safe_runnable' ? <ShieldCheck size={18} aria-hidden="true" /> : <TriangleAlert size={18} aria-hidden="true" />}
                <div>
                  <strong>{selectedTarget ? targetLabel(selectedTarget) : 'Browsing without a target'}</strong>
                  <Badge tone={detailAvailability.tone as Tone}>{detailAvailability.label}</Badge>
                  <p className="muted">{detailAvailability.detail}</p>
                </div>
              </div>
              {detailAvailability.id === 'safe_runnable' && canStartBoundedRun ? <Select label="Mapped bounded check" value={selectedCheckId} options={checkOptions} onChange={setSelectedCheckId} /> : null}
              {detailAvailability.id === 'safe_runnable' && !canStartBoundedRun ? <div className="form-banner neutral" role="note">Your role can review fit, but only owners, admins, and engineers can start bounded checks.</div> : null}
              <div className="vector-detail-actions">
                {detailAvailability.id === 'monitor_only' ? <AnchorButton href="#integrations" variant="secondary" size="sm">Open telemetry integrations</AnchorButton> : null}
                <Button variant="ghost" size="sm" onClick={() => setSelectedVector(null)}>Close</Button>
                {detailAvailability.id === 'safe_runnable' && canStartBoundedRun ? <Button size="sm" disabled={!selectedCheckId || busy !== ''} onClick={prepareRun}>Review run</Button> : null}
              </div>
            </div>
          </div>
        ) : null}
      </FormModal>

      <ConfirmModal
        open={Boolean(pendingRun)}
        title="Start this bounded check?"
        description={pendingRun && selectedTarget ? (
          <div className="stack-tight">
            <p><strong>Exact target:</strong> {targetLabel(selectedTarget)} <code>{targetId}</code></p>
            <p><strong>Target group:</strong> {targetGroupName}</p>
            <p><strong>Check:</strong> {plainCheckName(getString(pendingRun.check, ['name', 'title', 'check_id']))} <code>{getString(pendingRun.check, ['check_id'])}</code></p>
            <p><strong>Catalog vector:</strong> {getString(pendingRun.vector, ['vector_id'])}</p>
            <p><strong>Evidence limit:</strong> {evidenceCapabilityCopy(pendingRun.vector.evidence_capability).detail}</p>
            <p className="muted">Ownership, eligibility, concurrency, and rate limits are rechecked by the server before anything is sent.</p>
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
