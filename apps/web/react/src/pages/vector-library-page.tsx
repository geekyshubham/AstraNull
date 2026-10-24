import { useEffect, useMemo, useState } from 'react';
import { BookOpenCheck, ChevronDown, ChevronLeft, ChevronRight, Search, ShieldCheck, TriangleAlert, X } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { requiredInputMissing } from '../lib/missing-input.mjs';
import { CheckClassChips } from '../components/checks/check-class-chips';
import { RuleCoveragePanel } from '../components/rule-coverage/rule-coverage';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Select, type SelectOption } from '../components/ui/select';
import { Toast } from '../components/ui/toast';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import { ConfirmModal, FormModal } from '../lib/crud-ui';
import { requestJson } from '../lib/api';
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../lib/route-params';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName, plainCodeLabel, plainVerdictLabel } from '../lib/plain-language.mjs';
import { apiErrorMessage } from '../lib/error-messages';
import { checkPresentation } from '../lib/check-presentation.mjs';
import { isDeclarationOnlyCheck } from '../lib/check-classification.mjs';
import { hasEvidenceBackedVerdict, publishedRunVerdict } from '../lib/run-verdict';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate, formatNumber, formatTargetKind } from '../lib/utils';
import {
  CHECK_CATEGORIES,
  MISC_CATEGORY_ID,
  categorizeCheckGroups,
  countCompatibleSafeChecks,
  evidenceCapabilityCopy,
  groupVectorsByCheck,
  latestRunForCheckOnTarget,
  preferredRunnableCheck,
  searchAndFilterVectors,
  sortVectorsByTargetFit,
  vectorCheckSupportsTarget,
  vectorTargetAvailability,
  type VectorAvailability,
} from '../lib/vector-library.mjs';
import { PageHeader } from './page-components';
import './vector-library-page.css';
import { usePublishAssistantContext } from '../lib/assistant-page-store';

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

function targetLabel(target: DataItem) {
  const value = getString(target, ['value', 'hostname', 'id'], 'Unnamed target');
  return `${value} · ${formatTargetKind(getString(target, ['kind'], ''), value)}`;
}

const VERIFIED_OWNERSHIP_STATES = new Set(['dns_verified', 'provider_verified', 'user_confirmed']);

function targetOwnershipLabel(target: DataItem | null) {
  if (!target) return '';
  const verification = target.verification && typeof target.verification === 'object' && !Array.isArray(target.verification)
    ? target.verification as DataItem
    : null;
  const state = (getString(target, ['verification_state'], '') || getString(verification, ['state'], '') || getString(target, ['verify_state'], '')).toLowerCase();
  if (!state) return '';
  return VERIFIED_OWNERSHIP_STATES.has(state) ? 'Verified' : 'Not verified';
}

function checkUpperBound(check: DataItem) {
  const profile = check.probe_profile && typeof check.probe_profile === 'object' && !Array.isArray(check.probe_profile)
    ? check.probe_profile as DataItem
    : {};
  const maxRequests = Number(profile.max_requests);
  if (!Number.isFinite(maxRequests) || maxRequests <= 0) return 'Not recorded in the catalog';
  const timeoutMs = Number(profile.timeout_ms);
  const requests = `${formatNumber(maxRequests)} ${maxRequests === 1 ? 'request' : 'requests'}`;
  return Number.isFinite(timeoutMs) && timeoutMs > 0 ? `${requests}, ${formatNumber(timeoutMs)} ms timeout` : requests;
}

function initialTargetAvailability() {
  const fit = getRouteParam('fit');
  if (fit === 'all') return '';
  if (TARGET_AVAILABILITY_OPTIONS.some((option) => option.value === fit)) return fit;
  return getRouteParam('target') ? 'safe_runnable' : '';
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

function MappedCheckLatestRun({ run, evidence }: { run: DataItem | null; evidence: DataItem[] }) {
  if (!run) return <span className="vector-mapped-run muted small">Not run on this target</span>;
  const runId = getString(run, ['id']);
  const notTested = requiredInputMissing(run);
  const verdictValue = hasEvidenceBackedVerdict(run, evidence) ? publishedRunVerdict(run) : '';
  const outcome = notTested ? notTested.label : verdictValue ? plainVerdictLabel(verdictValue) : plainCodeLabel(getString(run, ['status'], 'planned'));
  const when = formatDate(run.started_at ?? run.created_at);
  return (
    <span className="vector-mapped-run small">
      {runId ? <a className="detail-entity-link" href={buildDetailHref('run-detail', runId)}>{outcome}</a> : <span>{outcome}</span>}
      <span className="muted"> · {when}</span>
    </span>
  );
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
  const [targetAvailability, setTargetAvailability] = useState(initialTargetAvailability);
  const [page, setPage] = useState(readInitialPage);
  const [expandedChecks, setExpandedChecks] = useState<Set<string>>(() => new Set());
  const [showUnmapped, setShowUnmapped] = useState(false);
  const [category, setCategory] = useState(() => getRouteParam('category'));
  const [targets, setTargets] = useState<DataItem[]>([]);
  const [targetsStatus, setTargetsStatus] = useState<'loading' | 'loaded' | 'error'>('loading');
  const [targetsError, setTargetsError] = useState('');
  const [targetId, setTargetId] = useState(() => getRouteParam('target'));
  const [selectedVector, setSelectedVector] = useState<DataItem | null>(null);
  const [selectedCheckId, setSelectedCheckId] = useState('');
  const [pendingRun, setPendingRun] = useState<{ vector: DataItem; check: DataItem; availability: VectorAvailability } | null>(null);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState<{ text: string; targetId: string } | null>(null);
  const [error, setError] = useState('');
  const [targetReloadKey, setTargetReloadKey] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    const onHashChange = () => {
      const next = getRouteParam('target');
      if (next !== targetId) chooseTarget(next);
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, [targetId]);

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

  // Target-first: one declared-target list; fit is computed for the selected target only.
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
    replaceRouteParams({
      target: targetId || null,
      fit: targetId ? targetAvailability || 'all' : null,
      q: query.trim() || null,
      category: category || null,
      page: page > 0 ? String(page + 1) : null,
    });
  }, [targetId, targetAvailability, query, category, page]);

  const selectedTarget = targets.find((target) => getString(target, ['id']) === targetId) ?? null;
  const missingDeepLinkTarget = Boolean(targetId) && targetsStatus === 'loaded' && !selectedTarget;

  const runnableChecks = data.checks.filter((check) => !isDeclarationOnlyCheck(check)
    && ['safe', 'soc_gated'].includes(getString(check, ['safety_class'])));
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
  const compatibleRunnableCount = fitForSelected?.status === 'loaded'
    ? countCompatibleSafeChecks(fitForSelected.checks, data.checks)
    : 0;
  const effectiveTargetAvailability = selectedTarget ? targetAvailability : '';

  const filteredVectors = useMemo(() => sortVectorsByTargetFit(searchAndFilterVectors(vectors, {
    query,
    section,
    capability,
    execution,
    targetAvailability: effectiveTargetAvailability,
    checks: data.checks,
    target: selectedTarget,
  }), data.checks, selectedTarget), [vectors, query, section, capability, execution, effectiveTargetAvailability, data.checks, selectedTarget]);

  const [filterSignature, setFilterSignature] = useState(`${section}|${capability}|${execution}|${targetAvailability}|${category}`);
  useEffect(() => {
    const signature = `${section}|${capability}|${execution}|${targetAvailability}|${category}`;
    if (signature !== filterSignature) {
      setFilterSignature(signature);
      setPage(0);
    }
  }, [section, capability, execution, targetAvailability, category, filterSignature]);
  // Check-first hierarchy: the filtered vectors are grouped under the checks that cover them,
  // so the catalog reads as checks with their vectors nested instead of a flat vector dump.
  const catalogGroups = useMemo(() => groupVectorsByCheck(filteredVectors, data.checks), [filteredVectors, data.checks]);
  const categorized = useMemo(() => categorizeCheckGroups(catalogGroups.groups, catalogGroups.unmapped, category), [catalogGroups, category]);
  const checkGroups = categorized.groups;
  const unmappedVectors = categorized.unmapped;
  const categoryChips = [
    { id: '', label: 'All', count: categorized.counts.all },
    ...CHECK_CATEGORIES.map((entry) => ({ id: entry.id, label: entry.label, count: categorized.counts[entry.id] ?? 0 })),
    { id: MISC_CATEGORY_ID, label: 'Miscellaneous', count: categorized.counts[MISC_CATEGORY_ID] ?? 0 },
  ];
  const pageCount = Math.max(1, Math.ceil(checkGroups.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visibleCheckGroups = checkGroups.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const sectionOptions: SelectOption[] = [
    { value: '', label: 'All catalog sections' },
    ...[...new Set(vectors.map((vector) => getString(vector, ['section'])).filter(Boolean))]
      .sort()
      .map((value) => ({ value, label: value })),
  ];
  const activeFilters = [
    category ? `Category: ${categoryChips.find((chip) => chip.id === category)?.label ?? category}` : '',
    section ? `Section: ${section}` : '',
    capability ? `Evidence: ${CAPABILITY_OPTIONS.find((option) => option.value === capability)?.label ?? capability}` : '',
    execution ? `Execution: ${EXECUTION_OPTIONS.find((option) => option.value === execution)?.label ?? execution}` : '',
    effectiveTargetAvailability ? `Fit: ${TARGET_AVAILABILITY_OPTIONS.find((option) => option.value === effectiveTargetAvailability)?.label ?? effectiveTargetAvailability}` : '',
    query.trim() ? `Search: “${query.trim()}”` : '',
  ].filter(Boolean);
  usePublishAssistantContext({
    route: 'checks',
    filters: {
      category: category || undefined,
      section: section || undefined,
      evidence: capability || undefined,
      execution: execution || undefined,
      fit: effectiveTargetAvailability || undefined,
      search: query.trim() || undefined,
    },
    facts: {
      'Checks shown': loading ? undefined : checkGroups.length,
      'Runnable checks': runnableChecks.length,
      'Fit target': selectedTarget ? getString(selectedTarget, ['value', 'id']) : undefined,
      'Compatible runnable checks': fitForSelected?.status === 'loaded' ? compatibleRunnableCount : undefined,
    },
  });

  function clearFilters() {
    setQuery('');
    setCategory('');
    setSection('');
    setCapability('');
    setExecution('');
    setTargetAvailability('');
    setPage(0);
  }

  function chooseTarget(next: string) {
    setTargetId(next);
    setTargetAvailability(next ? 'safe_runnable' : '');
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

  function toggleCheck(checkId: string) {
    setExpandedChecks((current) => {
      const next = new Set(current);
      if (next.has(checkId)) next.delete(checkId); else next.add(checkId);
      return next;
    });
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
    if (!selectedVector || !selectedTarget) return;
    const availability = vectorTargetAvailability(selectedVector, data.checks, selectedTarget);
    const check = availability.runnableChecks.find((candidate) => getString(candidate, ['check_id']) === selectedCheckId);
    if (!check) {
      setError('Select one mapped check before continuing.');
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
    if (!pendingRun || !selectedTarget) return;
    const checkId = getString(pendingRun.check, ['check_id']);
    setBusy('start-run');
    setError('');
    setMessage(null);
    try {
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_id: targetId, check_id: checkId },
      });
      setMessage({
        text: `Bounded check ${checkPresentation(pendingRun.check).name} started on ${getString(selectedTarget, ['value'], targetId)}. Its result and evidence are recorded on the target.`,
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

  const vectorRow = (vector: DataItem) => {
    const evidence = evidenceCapabilityCopy(vector.evidence_capability);
    const tier = getString(vector, ['evidence_tier'], '');
    const vectorId = getString(vector, ['vector_id'], 'No ID');
    const name = plainCheckName(getString(vector, ['canonical_name'], 'Unnamed vector'));
    const description = getString(vector, ['targeted_resource_or_assumption'], '');
    return (
      <li key={getString(vector, ['vector_id'])} className="vector-check-vector">
        <button
          type="button"
          className="vector-row-button"
          onClick={() => openVector(vector)}
          aria-label={`Review ${name} (${vectorId})`}
        >
          <span className="vector-row-copy">
            <span className="vector-row-title">
              <span className="vector-row-name">{name}</span>
              <code className="vector-row-id">{vectorId}</code>
            </span>
            {description ? <span className="vector-row-desc">{description}</span> : null}
          </span>
          <span className="vector-row-tier" title={evidence.detail} data-tone={evidence.tone}>{tier ? `${tier} · ${evidence.label}` : evidence.label}</span>
          <ChevronRight className="vector-row-chevron" size={16} aria-hidden="true" />
        </button>
      </li>
    );
  };

  const detailAvailability = selectedVector ? vectorTargetAvailability(selectedVector, data.checks, selectedTarget) : null;
  const detailRunnable = (detailAvailability?.runnableChecks ?? []).length > 0;
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
      label: `${checkPresentation(check).name}${recommended === check ? ' (semantic match)' : ''}`,
    })),
  ];
  const checkHref = (checkId: string) => `${buildDetailHref('check-detail', checkId)}${selectedTarget ? `&target=${encodeURIComponent(targetId)}` : ''}`;

  return (
    <div className="content vector-library-page">
      <PageHeader
        route="checks"
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
          <dd className="vector-fact-hint">Customer-safe subset of the check catalog; SOC-gated checks are not counted.</dd>
        </div>
        {selectedTarget ? (
          <div>
            <dt>Fit this target</dt>
            <dd className="tabular-nums">{!fitForSelected || fitForSelected.status === 'loading' ? 'Checking' : fitForSelected.status === 'error' ? 'Unavailable' : formatNumber(compatibleRunnableCount)}</dd>
            <dd className="vector-fact-hint">Customer-safe checks that support {getString(selectedTarget, ['value', 'hostname'], targetId)}</dd>
          </div>
        ) : null}
        <div>
          <dt>Launch access</dt>
          <dd>{canStartBoundedRun ? 'Can start checks' : 'Review only'}</dd>
          <dd className="vector-fact-hint">Ownership and rate gates still apply</dd>
        </div>
      </dl>
      {message ? (
        <Toast
          message={
            <span className="row-actions">
              <span>{message.text}</span>
              {message.targetId ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-detail', message.targetId)}>Open target</AnchorButton> : null}
            </span>
          }
          tone="success"
          duration={5000}
          onDismiss={() => setMessage(null)}
        />
      ) : null}
      {error ? (
        <Toast
          message={error}
          tone="error"
          duration={5000}
          onDismiss={() => setError('')}
        />
      ) : null}

      <Card className="vector-catalog-card">
        <CardHeader>
          <div>
            <CardTitle>Checks and the vectors they cover</CardTitle>
            <CardDescription>
              {loading ? 'Loading catalog…' : `${formatNumber(checkGroups.length)} ${checkGroups.length === 1 ? 'check' : 'checks'} cover ${formatNumber(filteredVectors.length)} matching ${filteredVectors.length === 1 ? 'vector' : 'vectors'}. Expand a check to see the vectors it exercises.`}
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent className="vector-catalog-body">
          <div className="vector-category-chips" role="group" aria-label="Check category">
            {categoryChips.map((chip) => (
              <button
                key={chip.id || 'all'}
                type="button"
                className="vector-category-chip"
                aria-pressed={category === chip.id}
                title={chip.id === MISC_CATEGORY_ID ? 'Vectors with no runnable check yet' : undefined}
                onClick={() => { setCategory(chip.id); if (chip.id === MISC_CATEGORY_ID) setShowUnmapped(true); }}
              >
                {chip.label}
                <span className="vector-category-count tabular-nums">{loading ? '…' : formatNumber(chip.count)}</span>
              </button>
            ))}
          </div>
          <div className="vector-library-controls" role="group" aria-label="Vector library filters" data-has-target={selectedTarget ? 'true' : undefined}>
            <label className="field vector-search-field"><span className="sr-only">Search</span><span className="vector-search-control"><Search size={15} aria-hidden="true" /><input type="search" value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} placeholder="Search checks and vectors by name, ID, protocol or control" aria-label="Search the vector catalog" /></span></label>
            {selectedTarget ? <Select label="Fit for target" value={targetAvailability} options={TARGET_AVAILABILITY_OPTIONS} onChange={setTargetAvailability} /> : null}
          </div>
          {targetId ? (
            <div className="vector-target-chip-row">
              <span className="vector-target-chip">
                <span>Fit for <strong>{selectedTarget ? getString(selectedTarget, ['value', 'hostname'], targetId) : targetId}</strong></span>
                <button type="button" className="vector-target-chip-clear" aria-label="Clear target fit" onClick={() => chooseTarget('')}><X size={14} aria-hidden="true" /></button>
              </span>
              {selectedTarget ? <a className="small" href={buildDetailHref('target-detail', targetId)}>Open target</a> : null}
            </div>
          ) : null}
          {targetId && targetsStatus === 'error' ? (
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
          <div className="vector-filter-summary">
            <Button size="sm" variant="ghost" aria-expanded={showAdvanced} aria-controls="vector-advanced-filters" onClick={() => setShowAdvanced((open) => !open)}>
              <ChevronDown className="vector-filter-chevron" size={14} aria-hidden="true" data-open={showAdvanced || undefined} />
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
            loadError ? (
              <EmptyState icon={BookOpenCheck} title="The catalog could not be loaded." body={loadError} actionLabel="Retry" onAction={() => setReloadKey((value) => value + 1)} />
            ) : checkGroups.length === 0 ? (
              unmappedVectors.length > 0 ? null
                : vectors.length > 0 ? (
                  <EmptyState
                    icon={BookOpenCheck}
                    title="No checks match these filters."
                    body={activeFilters.join(' · ') || 'Adjust the search or filters.'}
                    actionLabel="Clear filters"
                    onAction={clearFilters}
                    actions={effectiveTargetAvailability
                      ? <Button variant="ghost" onClick={() => { setTargetAvailability(''); setPage(0); }}>Show all fits</Button>
                      : undefined}
                  />
                ) : <EmptyState icon={BookOpenCheck} title="The check catalog is empty." body="No catalog entries were returned for this workspace." />
            ) : (
              <ul className="vector-check-groups">
                {visibleCheckGroups.map((group) => {
                  const check = group.check as DataItem;
                  const expanded = expandedChecks.has(group.checkId);
                  const fits = selectedTarget ? vectorCheckSupportsTarget(check, selectedTarget) : null;
                  const vectorCount = group.vectors.length;
                  return (
                    <li key={group.checkId} className="vector-check-group" data-expanded={expanded || undefined}>
                      <div className="vector-check-head">
                        <button
                          type="button"
                          className="vector-check-toggle"
                          aria-expanded={expanded}
                          aria-controls={`vc-${group.checkId}`}
                          onClick={() => toggleCheck(group.checkId)}
                        >
                          <ChevronDown className="vector-check-chevron" size={16} aria-hidden="true" data-open={expanded || undefined} />
                          <span className="vector-check-title">
                            <strong title={group.checkId}>{plainCheckName(checkPresentation(check).name)}</strong>
                          </span>
                        </button>
                        <span className="vector-check-meta">
                          <CheckClassChips check={check} />
                          <Badge tone="muted">{vectorCount} {vectorCount === 1 ? 'vector' : 'vectors'}</Badge>
                          {selectedTarget ? <Badge tone={fits ? 'success' : 'muted'}>{fits ? 'Fits target' : 'Target not supported'}</Badge> : null}
                          <AnchorButton size="sm" variant="secondary" href={checkHref(group.checkId)} aria-label={`Open check ${plainCheckName(checkPresentation(check).name)}`}>Open check</AnchorButton>
                        </span>
                      </div>
                      {expanded ? <ul className="vector-check-vectors" id={`vc-${group.checkId}`}>{group.vectors.map(vectorRow)}</ul> : null}
                    </li>
                  );
                })}
              </ul>
            )
          )}
          {!loading && !loadError && unmappedVectors.length > 0 && (checkGroups.length === 0 || safePage === pageCount - 1) ? (
            <div className="vector-check-group vector-check-group--misc" data-expanded={showUnmapped || undefined}>
              <div className="vector-check-head">
                <button
                  type="button"
                  className="vector-check-toggle"
                  aria-expanded={showUnmapped}
                  aria-controls="vector-unmapped-list"
                  onClick={() => setShowUnmapped((open) => !open)}
                >
                  <ChevronDown className="vector-check-chevron" size={16} aria-hidden="true" data-open={showUnmapped || undefined} />
                  <span className="vector-check-title">
                    <strong>Miscellaneous</strong>
                  </span>
                  <span className="vector-check-sub">{formatNumber(unmappedVectors.length)} {unmappedVectors.length === 1 ? 'vector' : 'vectors'} · no runnable check yet</span>
                </button>
              </div>
              {showUnmapped ? <ul className="vector-check-vectors" id="vector-unmapped-list">{unmappedVectors.map(vectorRow)}</ul> : null}
            </div>
          ) : null}
          {!loading && !loadError && checkGroups.length > 0 ? (
            <nav className="vector-pagination" aria-label="Check catalog pages">
              <span className="muted">Page {safePage + 1} of {pageCount} · checks {safePage * PAGE_SIZE + 1}-{Math.min((safePage + 1) * PAGE_SIZE, checkGroups.length)} of {checkGroups.length}</span>
              <span className="vector-pagination-actions">
                <Button size="sm" variant="secondary" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}><ChevronLeft size={15} aria-hidden="true" /> Previous</Button>
                <Button size="sm" variant="secondary" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next <ChevronRight size={15} aria-hidden="true" /></Button>
              </span>
            </nav>
          ) : null}
        </CardContent>
      </Card>

      <Card className="vector-rule-coverage-card" id="rule-coverage">
        <CardContent className="stack">
          <RuleCoveragePanel config={config} session={session} />
          {selectedTarget ? (
            <p className="muted small row-actions">
              <span>See the current status of each rule family on {getString(selectedTarget, ['value', 'hostname'], targetId)}.</span>
              <AnchorButton size="sm" variant="secondary" href={`${buildDetailHref('target-detail', targetId)}&tab=coverage`}>Open target rule coverage</AnchorButton>
            </p>
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
            <div className="vector-detail-rail" role="group" aria-label="Target fit and launch">
              <div className="vector-target-note" role="note">
                {detailRunnable ? <ShieldCheck size={18} aria-hidden="true" /> : <TriangleAlert size={18} aria-hidden="true" />}
                <div>
                  <strong>{selectedTarget ? targetLabel(selectedTarget) : 'Browsing without a target'}</strong>
                  <Badge tone={detailAvailability.tone as Tone}>{detailAvailability.label}</Badge>
                  <p className="muted">{detailAvailability.detail}</p>
                </div>
              </div>
              {detailRunnable && canStartBoundedRun ? <Select label="Mapped bounded check" value={selectedCheckId} options={checkOptions} onChange={setSelectedCheckId} /> : null}
              {detailRunnable && !canStartBoundedRun ? <div className="form-banner neutral" role="note">Your role can review fit, but only owners, admins, and engineers can start bounded checks.</div> : null}
              <div className="vector-detail-actions">
                {detailAvailability.id === 'monitor_only' ? <AnchorButton href="#integrations" variant="secondary" size="sm">Open telemetry integrations</AnchorButton> : null}
                <Button variant="ghost" size="sm" onClick={() => setSelectedVector(null)}>Close</Button>
                {detailRunnable && canStartBoundedRun ? <Button size="sm" disabled={!selectedCheckId || busy !== ''} onClick={prepareRun}>Review run</Button> : null}
              </div>
            </div>
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
                      const latestRun = selectedTarget ? latestRunForCheckOnTarget(data.runs, checkId, targetId) : null;
                      return (
                        <li key={checkId}>
                          {check ? <a href={checkHref(checkId)}>{checkPresentation(check).name}</a> : <span>{checkId}</span>}
                          <code className="traffic-path-label">{checkId}</code>
                          {check ? <CheckClassChips check={check} /> : null}
                          {!check ? <span className="muted small"> not in the current catalog</span> : null}
                          {selectedTarget ? <MappedCheckLatestRun run={latestRun} evidence={data.evidence} /> : null}
                        </li>
                      );
                    })}
                  </ul>
                ) : <p>No bounded check is mapped. This vector is explanatory only.</p>}
                {mappedCheckIds.length && selectedTarget ? <p className="muted small">Latest result per check on {getString(selectedTarget, ['value'], targetId)}, from recent runs.</p> : null}
              </section>
            </div>
          </div>
        ) : null}
      </FormModal>

      <ConfirmModal
        open={Boolean(pendingRun)}
        title={pendingRun && selectedTarget
          ? `Start ${checkPresentation(pendingRun.check).name} on ${getString(selectedTarget, ['value', 'hostname'], targetId)}?`
          : 'Start this check?'}
        description={pendingRun && selectedTarget ? (
          <div className="stack-tight scan-review">
            <dl className="td-review-list">
              <div><dt>Target</dt><dd>{targetLabel(selectedTarget)} <code>{targetId}</code></dd></div>
              <div><dt>Check</dt><dd>{checkPresentation(pendingRun.check).name} <code>{getString(pendingRun.check, ['check_id'])}</code></dd></div>
              <div><dt>Upper bound</dt><dd>{checkUpperBound(pendingRun.check)}</dd></div>
              {targetOwnershipLabel(selectedTarget) ? <div><dt>Ownership</dt><dd>{targetOwnershipLabel(selectedTarget)}</dd></div> : null}
              <div><dt>Evidence limit</dt><dd>{evidenceCapabilityCopy(pendingRun.vector.evidence_capability).detail}</dd></div>
              <div><dt>Catalog vector</dt><dd><code>{getString(pendingRun.vector, ['vector_id'])}</code></dd></div>
            </dl>
            <p className="muted">The server re-checks ownership, safe windows, rate and concurrency gates when you start. A bounded check does not measure volumetric capacity.</p>
          </div>
        ) : ''}
        confirmLabel="Start check"
        confirmTone="default"
        busy={busy === 'start-run'}
        onCancel={() => setPendingRun(null)}
        onConfirm={() => void startRun()}
      />
    </div>
  );
}
