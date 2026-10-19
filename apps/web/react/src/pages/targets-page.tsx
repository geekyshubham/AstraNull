import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import {
  Play,
  Plus,
  Search,
  Tags,
  Target,
  Trash2
} from 'lucide-react';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { requestJson } from '../lib/api';
import { apiErrorMessage } from '../lib/error-messages';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../lib/route-params';
import { formatDate, formatNumber, formatTargetKind } from '../lib/utils';
import { resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { DataTable, type TableColumn } from '../components/ui/table';
import { RowActionsMenu, type RowAction } from '../components/ui/row-actions-menu';
import { EmptyState } from '../components/ui/empty-state';
import { Toast } from '../components/ui/toast';
import { FormModal, useConfirmModal } from '../lib/crud-ui';
import { canonicalCohortFilters, COHORT_FILTER_KEYS, inventoryUnits } from '../lib/domain-checks.mjs';
import { TargetCsvImportButton } from '../components/targets/target-csv-import';
import { DomainFavicon } from '../components/targets/domain-favicon';
import { TargetCohortList } from '../components/targets/target-cohort';
import { useListReturnState, useRestoreListPosition } from '../components/evidence/use-inspector';
import { EVIDENCE_STATUS_TONE, latestEvidenceRunByTarget, latestRunVerdict } from '../lib/dashboard-metrics';
// @ts-ignore Plain ESM keeps run-start role parity testable with node:test.
import { canStartRun } from '../lib/run-permissions.mjs';
import { useDesignVariant } from '../lib/design-variant';
import { VariantSwitch } from '../components/ui/variant-switch';
import { TargetsRefinedInventory, type TargetRowModel } from './refined/targets-refined';
import { computeSubdomainGrouping } from '../lib/subdomain-grouping';
import { usePublishAssistantContext } from '../lib/assistant-page-store';

const TARGETS_PAGE_STYLES = `
.targets-page .targets-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; background: var(--border-soft); gap: 1px; }
.targets-page .targets-summary-cell { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1); padding: var(--space-4); background: var(--surface); }
.targets-page .targets-summary-cell span { color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-summary-cell small { color: var(--fg-2); font-size: var(--text-xs); line-height: 1.4; }
.targets-page .target-unknown { color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-summary-cell strong { color: var(--fg); font-family: var(--font-display); font-size: var(--text-xl); font-variant-numeric: tabular-nums; }
.targets-page .targets-intake { border-color: color-mix(in oklab, var(--accent), transparent 70%); }
.targets-page .targets-intake-form { display: grid; grid-template-columns: minmax(200px, 1fr) minmax(200px, 1.15fr) minmax(200px, 1fr); gap: var(--space-4) var(--space-3); align-items: start; }
.targets-page .targets-intake-form label { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1-5); color: var(--fg); font-size: var(--text-sm); font-weight: 500; }
.targets-page .targets-intake-field { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1-5); }
.targets-page .targets-intake-field small { color: var(--fg-2); font-size: var(--text-xs); line-height: 1.4; }
.targets-page .targets-intake-form > .btn { justify-self: start; }
.targets-page .target-validation { display: inline-flex; align-items: center; gap: var(--space-2); white-space: nowrap; }
.targets-page .target-validation .target-date { color: var(--muted); }
.targets-page .targets-intake-form input, .targets-page .targets-intake-form select { width: 100%; min-height: 42px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); padding: 8px 12px; }
.targets-page .targets-toolbar { display: grid; grid-template-columns: minmax(240px, 1.5fr) repeat(3, minmax(150px, 1fr)); align-items: end; gap: var(--space-3); margin-bottom: var(--space-3); }
.targets-page .targets-search { display: flex; min-width: 0; align-items: center; gap: var(--space-2); min-height: 44px; border: 1px solid var(--border); border-radius: var(--radius-pill); background: var(--surface-sunk); padding: 0 var(--space-3); }
.targets-page .targets-search input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fg); }
.targets-page .targets-filter { display: flex; min-width: 0; flex-direction: column; gap: var(--space-1); color: var(--fg-2); font-size: var(--text-xs); }
body .targets-page .targets-filter > span { color: var(--fg-2); font-family: var(--font-body); font-size: var(--text-xs); font-weight: 500; letter-spacing: normal; text-transform: none; }
.targets-page .targets-filter select { width: 100%; min-height: 44px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface-sunk); color: var(--fg); padding: 8px 10px; }
.targets-page .targets-result-count { margin: 0 0 var(--space-3); color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .target-primary { display: flex; min-width: 0; align-items: center; gap: var(--space-3); }
.targets-page .target-primary-icon { display: inline-grid; width: 36px; height: 36px; flex: none; place-items: center; border-radius: var(--radius-md); background: var(--wash); color: var(--fg-2); transition: background-color var(--motion-fast) var(--ease-out-soft), color var(--motion-fast) var(--ease-out-soft); }
.targets-page .target-primary-copy { display: flex; min-width: 0; flex-direction: column; gap: 2px; }
.targets-page a.target-primary-name { display: block; min-width: 0; max-width: 100%; border-radius: var(--radius-sm); color: var(--fg); text-decoration: none; }
.targets-page a.target-primary-name::after { content: ''; position: absolute; inset: 0; }
.targets-page a.target-primary-name:hover strong, .targets-page a.target-primary-name:focus-visible strong { text-decoration: underline; text-decoration-color: var(--border-strong); text-decoration-thickness: 1px; text-underline-offset: 3px; }
.targets-page a.target-primary-name:focus-visible { outline: none; }
.targets-page a.target-primary-name:focus-visible::after { border-radius: var(--radius-sm); box-shadow: inset 0 0 0 var(--focus-ring-width) var(--focus-color); }
.targets-page .target-primary-name strong { display: block; max-width: 44ch; overflow: hidden; color: var(--fg); font-family: var(--font-body); font-size: var(--text-base); font-weight: 600; letter-spacing: -0.01em; text-overflow: ellipsis; white-space: nowrap; }
.targets-page .target-primary-meta { display: flex; min-width: 0; align-items: center; gap: var(--space-1-5); color: var(--fg-2); font-size: var(--text-xs); white-space: nowrap; }
.targets-page .target-tag-chip { display: inline-flex; min-width: 0; max-width: 22ch; align-items: center; gap: var(--space-1); overflow: hidden; padding: 0 var(--space-1-5); border-radius: var(--radius-pill); background: var(--wash); color: var(--fg-2); text-overflow: ellipsis; }
.targets-page .target-tag-more { flex: none; color: var(--muted); }
.targets-page .target-status { display: inline-flex; align-items: center; gap: var(--space-2); color: var(--fg-2); font-size: var(--text-sm); white-space: nowrap; }
.targets-page .target-status-dot { width: 8px; height: 8px; flex: none; border-radius: var(--radius-pill); box-shadow: inset 0 0 0 1.5px var(--border-strong); }
.targets-page .target-status[data-tone='verified'] { color: var(--fg); }
.targets-page .target-status[data-tone='verified'] .target-status-dot { background: var(--success); box-shadow: none; }
.targets-page .target-status[data-tone='pending'] .target-status-dot { background: var(--warn); box-shadow: none; }
.targets-page .target-unknown { color: var(--fg-2); font-size: var(--text-sm); }
.targets-page .target-row-actions { display: flex; flex-wrap: nowrap; align-items: center; justify-content: flex-end; gap: var(--space-1-5); width: max-content; margin-left: auto; }
.targets-page .target-row-actions > * { position: relative; z-index: 1; }
.targets-page .targets-intake-tags { grid-column: 1 / -1; }
.targets-page .field-error { color: var(--danger); font-size: var(--text-xs); }
.targets-page .target-row-actions .btn { min-height: 34px; }
.targets-page .targets-table-wrap .data-table { min-width: 720px; table-layout: fixed; }
.targets-page .targets-table-wrap .data-table thead th { color: var(--fg-2); font-family: var(--font-body); font-size: var(--text-xs); font-weight: 500; letter-spacing: normal; text-transform: none; }
.targets-page .targets-table-wrap .data-table td { padding-block: var(--space-3); vertical-align: middle; }
.targets-page .targets-table-wrap .data-table :is(th, td):nth-child(1) { width: 46%; position: relative; }
.targets-page .targets-table-wrap .data-table :is(th, td):nth-child(2) { width: 16%; }
.targets-page .targets-table-wrap .data-table :is(th, td):nth-child(3) { width: 18%; }
.targets-page .targets-table-wrap .data-table :is(th, td):nth-child(4) { width: 20%; }
.targets-page .targets-table-wrap .data-table :is(th, td):not(:first-child) { white-space: nowrap; }
.targets-page .targets-table-wrap .data-table thead th:last-child { text-align: right; }
.targets-page .targets-table-wrap .data-table :is(th, td) { padding-inline: var(--space-3); }
.targets-page .targets-table-wrap .data-table :is(th, td):first-child { padding-left: var(--space-4); }
.targets-page .targets-table-wrap .data-table :is(th, td):last-child { padding-right: var(--space-4); }
.targets-page .targets-table-wrap .data-table tbody tr { transition: background-color var(--motion-fast) var(--ease-out-soft); }
.targets-page .targets-table-wrap .data-table tbody tr:hover { background: var(--surface-hover); }
.targets-page .targets-table-wrap .data-table tbody tr:hover .target-primary-icon { background: var(--wash-strong); color: var(--fg); }
@media (prefers-reduced-motion: reduce) { .targets-page .targets-table-wrap .data-table tbody tr, .targets-page .target-primary-icon { transition: none; } }
@media (max-width: 1120px) { .targets-page .targets-toolbar { grid-template-columns: repeat(3, minmax(0, 1fr)); } .targets-page .targets-search { grid-column: 1 / -1; } }
@media (max-width: 900px) {
  .targets-page .target-row-actions .btn { min-height: 44px; }
}
@media (max-width: 700px) {
  body .targets-page .targets-table-wrap { overflow: visible; border: 0; background: transparent; }
  body .targets-page .targets-table-wrap .data-table { display: block; min-width: 0; table-layout: auto; }
  body .targets-page .targets-table-wrap .data-table thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  body .targets-page .targets-table-wrap .data-table tbody { display: grid; gap: var(--space-2); }
  body .targets-page .targets-table-wrap .data-table tbody tr:not(.table-empty-row) { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-areas: 'target target' 'own result' 'actions actions'; gap: var(--space-3); padding: var(--space-3) var(--space-4); border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface); }
  body .targets-page .targets-table-wrap .data-table tbody tr:not(.table-empty-row) td { display: block; width: auto; padding: 0; border: 0; background: transparent; white-space: normal; }
  body .targets-page .targets-table-wrap .data-table tbody tr:not(.table-empty-row) td::before { display: none; content: none; }
  body .targets-page .targets-table-wrap .data-table tbody td:nth-child(1) { grid-area: target; position: static; }
  body .targets-page .targets-table-wrap .data-table tbody td:nth-child(2) { grid-area: own; align-self: center; }
  body .targets-page .targets-table-wrap .data-table tbody td:nth-child(3) { grid-area: result; align-self: center; text-align: end; }
  body .targets-page .targets-table-wrap .data-table tbody td:nth-child(4) { grid-area: actions; }
  .targets-page .target-row-actions { width: 100%; justify-content: flex-end; margin-left: 0; }
  .targets-page .target-primary-name strong { max-width: 100%; }
}
@media (max-width: 1000px) { .targets-page .targets-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } .targets-page .targets-intake-form { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 620px) { .targets-page .targets-intake-form, .targets-page .targets-toolbar { grid-template-columns: 1fr; } .targets-page .targets-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } .targets-page .targets-summary-cell { padding: var(--space-3); } .targets-page .targets-summary-cell small { display: none; } .targets-page .targets-search { grid-column: auto; } .targets-page .targets-intake-form .btn { width: 100%; } }
`;

type Tone = NonNullable<BadgeProps['tone']>;

/** ADR-0008 target kinds accepted by POST /v1/targets (src/contracts/targetManagement.mjs). */
const TARGET_KIND_OPTIONS: { value: string; label: string; hint: string; placeholder: string }[] = [
  { value: 'fqdn', label: 'FQDN / hostname', hint: 'Website or API hostname; ownership proven by DNS TXT record', placeholder: 'api.example.com' },
  { value: 'ip', label: 'IP address', hint: 'Single public IP, e.g. an origin behind a verified hostname', placeholder: '203.0.113.10' },
  { value: 'url', label: 'URL', hint: 'Specific path on a hostname', placeholder: 'https://api.example.com/health' },
  { value: 'tcp', label: 'TCP host:port', hint: 'Non-HTTP service, checked as the origin of a verified hostname', placeholder: '203.0.113.10:443' },
  { value: 'dns_zone', label: 'DNS zone', hint: 'Authoritative zone', placeholder: 'example.com' },
  { value: 'canary', label: 'Canary endpoint', hint: 'Endpoint you expect to stay reachable', placeholder: 'https://status.example.com' }
];

const UNDECIDED_BEHAVIOR = 'undecided';

/** What the declared edge should do with abusive traffic; recorded as a declaration, never as a verdict. */
const EXPECTED_BEHAVIOR_OPTIONS: { value: string; label: string; hint: string }[] = [
  { value: 'block_at_edge', label: 'Block at edge', hint: 'Block at edge \u2014 your CDN/WAF should stop abusive traffic before it reaches origin' },
  { value: 'absorb_at_origin', label: 'Absorb at origin', hint: 'Absorb at origin \u2014 origin is sized to take the load' },
  { value: 'rate_shape', label: 'Rate shape', hint: 'Rate shape \u2014 traffic is throttled, not blocked' },
  { value: UNDECIDED_BEHAVIOR, label: 'Not sure \u2014 decide later', hint: 'No expectation is recorded with this target. Each check still applies its own expected result.' }
];

const MAX_TARGET_TAGS = 16;
const TARGET_TAG_PATTERN = /^[a-z0-9][a-z0-9:_.-]{0,47}$/;

/**
 * Parse a comma-separated tag string the way the backend does (trim, lowercase, dedupe, validate,
 * cap at 16). Returns the normalized list plus the first validation error, if any.
 */
function parseTagInput(raw: string): { tags: string[]; error: string } {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const part of raw.split(',')) {
    const tag = part.trim().toLowerCase();
    if (!tag) continue;
    if (!TARGET_TAG_PATTERN.test(tag)) {
      return { tags, error: `Invalid tag "${tag}": use a–z, 0–9, and : _ . - (max 48 chars, no leading symbol).` };
    }
    if (seen.has(tag)) continue;
    seen.add(tag);
    tags.push(tag);
  }
  if (tags.length > MAX_TARGET_TAGS) {
    return { tags, error: `At most ${MAX_TARGET_TAGS} tags are allowed per target.` };
  }
  return { tags, error: '' };
}

/** Read the stored tag list off a target record (top-level `tags`, then metadata.tags). */
/**
 * Server cohort filters carried in the address (dashboard and analytics links). `verification` is
 * this page's own filter over the complete inventory (it groups pending with unverified), so it
 * never turns the page into a server cohort.
 */
function readCohortFromAddress(): Record<string, string> | null {
  const hash = window.location.hash.replace(/^#/, '');
  const params = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '');
  params.delete('verification');
  return canonicalCohortFilters(params);
}

const COHORT_ADDRESS_KEYS = [...COHORT_FILTER_KEYS, 'search', 'group', 'target_group', 'verification_state', 'role'];

function targetTags(item: DataItem): string[] {
  if (Array.isArray(item.tags)) return item.tags.filter((tag): tag is string => typeof tag === 'string');
  const metadata = item.metadata && typeof item.metadata === 'object' && !Array.isArray(item.metadata) ? item.metadata as DataItem : null;
  if (metadata && Array.isArray(metadata.tags)) return (metadata.tags as unknown[]).filter((tag): tag is string => typeof tag === 'string');
  return [];
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function verificationState(item: DataItem) {
  const verification = item.verification && typeof item.verification === 'object' && !Array.isArray(item.verification)
    ? item.verification as DataItem
    : null;
  return getString(verification, ['state'], getString(item, ['verification_state'], 'unverified'));
}

function isVerified(state: string) {
  return ['dns_verified', 'provider_verified', 'user_confirmed', 'verified'].includes(state.trim().toLowerCase());
}


function sourceLabel(item: DataItem) {
  const metadata = item.metadata && typeof item.metadata === 'object' && !Array.isArray(item.metadata)
    ? item.metadata as DataItem
    : null;
  const integration = getString(item, ['import_integration', 'import_source'], '');
  if (integration && integration !== '—') return integration;
  return getString(metadata, ['source_app', 'app', 'source'], getString(item, ['source'], 'manual'));
}

function targetHostname(item: DataItem) {
  const value = getString(item, ['value'], '').trim().toLowerCase();
  try {
    return /^[a-z][a-z0-9+.-]*:\/\//.test(value) ? new URL(value).hostname : value.replace(/\.$/, '');
  } catch {
    return value;
  }
}

function visibleTargetTags(item: DataItem): string[] {
  const host = targetHostname(item);
  return targetTags(item).filter((tag) => {
    const [key, ...rest] = tag.split(':');
    return key !== 'env' && key !== 'environment' && !(key === 'domain' && rest.join(':') === host);
  });
}

function TableDate({ value }: { value: unknown }) {
  const ts = value ? new Date(typeof value === 'number' ? value : String(value)).getTime() : Number.NaN;
  if (!Number.isFinite(ts)) return <span className="mono small target-date">{formatDate(value)}</span>;
  const minutes = Math.round(Math.max(0, Date.now() - ts) / 60000);
  const label = minutes < 1 ? 'just now'
    : minutes < 60 ? `${minutes}m ago`
      : minutes < 48 * 60 ? `${Math.round(minutes / 60)}h ago`
        : `${Math.round(minutes / 1440)}d ago`;
  return <span className="small target-date" title={formatDate(value)}>{label}</span>;
}

export function TargetsPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const { confirm } = useConfirmModal();
  const showVariantSwitch = session.principal === 'staff';
  // Only staff persist a layout preference; `#targets?variant=refined` works for every viewer.
  const [variant, setVariant] = useDesignVariant('targets', { persist: showVariantSwitch });
  const canWriteTargets = sessionHasPermission(session, 'target_group:write');
  const canWriteTargetsRef = useRef(canWriteTargets);
  canWriteTargetsRef.current = canWriteTargets;
  const { initial, save } = useListReturnState(session, 'targets');
  const urlVerification = getRouteParam('verification');
  const savedFilters: Record<string, string> = { ...(initial.filters ?? {}), ...(urlVerification ? { verification: urlVerification } : {}) };
  const [cohort, setCohort] = useState<Record<string, string> | null>(readCohortFromAddress);
  function consumeAddParam() {
    const requested = getRouteParam('add');
    if (!requested) return;
    if (requested === '1' && canWriteTargetsRef.current) setShowAdd(true);
    replaceRouteParams({ add: null });
  }
  useEffect(() => {
    const sync = () => {
      setCohort(readCohortFromAddress());
      consumeAddParam();
    };
    consumeAddParam();
    window.addEventListener('hashchange', sync);
    window.addEventListener('popstate', sync);
    return () => {
      window.removeEventListener('hashchange', sync);
      window.removeEventListener('popstate', sync);
    };
  }, []);
  const [query, setQuery] = useState(savedFilters.q ?? '');
  const [verificationFilter, setVerificationFilter] = useState(savedFilters.verification ?? 'all');
  const [kindFilter, setKindFilter] = useState(savedFilters.kind ?? 'all');
  const [tagFilter, setTagFilter] = useState(savedFilters.tag ?? 'all');
  const [showAdd, setShowAdd] = useState(() => canWriteTargets && getRouteParam('add') === '1');
  const [addKind, setAddKind] = useState('fqdn');
  const [addBehavior, setAddBehavior] = useState('block_at_edge');
  const kindSelectRef = useRef<HTMLSelectElement>(null);
  const addOpenerRef = useRef<HTMLElement | null>(null);
  const [addTags, setAddTags] = useState('');
  const [editTargetId, setEditTargetId] = useState('');
  const [editTags, setEditTags] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const canRunChecks = canStartRun(session.role);
  const targets = Array.isArray(data.targets) ? data.targets : [];
  const addTagsResult = parseTagInput(addTags);
  const editTagsResult = parseTagInput(editTags);
  const allTags = useMemo(
    () => [...new Set(targets.flatMap((item) => visibleTargetTags(item)))].sort(),
    [targets]
  );

  const subdomainGrouping = useMemo(() => computeSubdomainGrouping(targets), [targets]);
  // Top-level domains only; discovered subdomains are grouped under their parent and never counted here.
  const topLevelList = useMemo(() => targets.filter((item) => !subdomainGrouping.hiddenIds.has(getString(item, ['id'], ''))), [targets, subdomainGrouping]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return targets.filter((item) => {
      if (subdomainGrouping.hiddenIds.has(getString(item, ['id'], ''))) return false;
      const state = verificationState(item).toLowerCase();
      if (verificationFilter === 'verified' && !isVerified(state)) return false;
      if (verificationFilter === 'unverified' && isVerified(state)) return false;
      const kind = getString(item, ['kind'], 'unknown').toLowerCase();
      if (kindFilter !== 'all' && kind !== kindFilter) return false;
      if (tagFilter !== 'all' && !targetTags(item).includes(tagFilter)) return false;
      if (!needle) return true;
      return [
        getString(item, ['value'], ''),
        targetTags(item).join(' '),
        sourceLabel(item)
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [targets, query, verificationFilter, kindFilter, tagFilter, subdomainGrouping]);

  useEffect(() => {
    if (showAdd) kindSelectRef.current?.focus();
  }, [showAdd]);

  function openAddForm(opener: HTMLElement | null) {
    addOpenerRef.current = opener;
    setShowAdd(true);
  }

  function closeAddForm() {
    setShowAdd(false);
    const opener = addOpenerRef.current;
    addOpenerRef.current = null;
    window.requestAnimationFrame(() => opener?.focus());
  }

  const latestRuns = useMemo(() => latestEvidenceRunByTarget(Array.isArray(data.runs) ? data.runs : []), [data.runs]);
  const runsUnavailable = Boolean(data.loadErrors.runs);
  const addKindOption = TARGET_KIND_OPTIONS.find((option) => option.value === addKind) ?? TARGET_KIND_OPTIONS[0];
  const addBehaviorOption = EXPECTED_BEHAVIOR_OPTIONS.find((option) => option.value === addBehavior) ?? EXPECTED_BEHAVIOR_OPTIONS[0];

  const verifiedCount = topLevelList.filter((item) => isVerified(verificationState(item))).length;
  const unverifiedCount = topLevelList.length - verifiedCount;
  const units = useMemo(() => inventoryUnits(topLevelList), [topLevelList]);
  const filtersActive = Boolean(query.trim()) || verificationFilter !== 'all' || kindFilter !== 'all' || tagFilter !== 'all';
  usePublishAssistantContext({
    route: 'targets',
    filters: {
      search: query.trim() || undefined,
      ownership: verificationFilter === 'all' ? undefined : verificationFilter,
      kind: kindFilter === 'all' ? undefined : kindFilter,
      tag: tagFilter === 'all' ? undefined : tagFilter,
    },
    facts: {
      'Declared targets': topLevelList.length,
      'Ownership verified': verifiedCount,
      'Ownership not verified': unverifiedCount,
      'Shown with filters': filtersActive ? filtered.length : undefined,
      'Subdomains grouped': subdomainGrouping.hiddenIds.size || undefined,
    },
  });

  function clearCohort() {
    replaceRouteParams(Object.fromEntries(COHORT_ADDRESS_KEYS.map((key) => [key, null])));
    setCohort(null);
  }

  useEffect(() => {
    save({ filters: { q: query.trim(), verification: verificationFilter, kind: kindFilter, tag: tagFilter } });
  }, [save, query, verificationFilter, kindFilter, tagFilter]);
  useRestoreListPosition(data.loaded && filtered.length > 0, initial);

  function clearFilters() {
    setQuery('');
    setVerificationFilter('all');
    setKindFilter('all');
    setTagFilter('all');
  }

  function rememberRow(id: string, focusKey = `target-${id}`) {
    save({ selectedRowId: id, focusKey });
  }
  const targetKinds = [...new Set(targets.map((item) => getString(item, ['kind'], 'unknown').toLowerCase()).filter(Boolean))].sort();

  async function addTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteTargets) return;
    const form = new FormData(event.currentTarget);
    const value = String(form.get('value') ?? '').trim();
    if (!value) {
      setError('Target value is required.');
      return;
    }
    const { tags, error: tagError } = parseTagInput(addTags);
    if (tagError) {
      setError(tagError);
      return;
    }
    setBusy('add');
    setMessage('');
    setError('');
    try {
      const body: Record<string, unknown> = {
        kind: addKind,
        value,
        ...(addBehavior === UNDECIDED_BEHAVIOR ? {} : { expected_behavior: addBehavior }),
        tags
      };
      const created = await requestJson(config, session, '/v1/targets', { method: 'POST', body }) as DataItem;
      const createdId = getString(created, ['id'], '');
      // Onboarding: issue the DNS TXT ownership challenge straight away so the target page can
      // show the record, keep re-checking it, and start WAF/CDN detection once it verifies.
      if (createdId && addKind === 'fqdn') {
        await requestJson(config, session, `/v1/targets/${encodeURIComponent(createdId)}/dns-ownership/issue`, {
          method: 'POST',
          body: {}
        }).catch(() => undefined);
      }
      setMessage(`${value} added to declared scope. Verify ownership before running checks.`);
      save({ selectedRowId: createdId, focusKey: createdId ? `target-${createdId}` : undefined });
      setShowAdd(false);
      setAddTags('');
      setAddKind('fqdn');
      setAddBehavior('block_at_edge');
      await onRefresh();
      if (createdId) window.location.hash = `target-detail?id=${encodeURIComponent(createdId)}`;
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not add the target.'));
    } finally {
      setBusy('');
    }
  }

  function openTagEditor(item: DataItem) {
    setEditTargetId(getString(item, ['id'], ''));
    setEditTags(targetTags(item).join(', '));
    setMessage('');
    setError('');
  }

  async function saveTags(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteTargets || !editTargetId) return;
    const { tags, error: tagError } = parseTagInput(editTags);
    if (tagError) {
      setError(tagError);
      return;
    }
    setBusy(`tags-${editTargetId}`);
    setMessage('');
    setError('');
    try {
      await requestJson(config, session, `/v1/targets/${encodeURIComponent(editTargetId)}`, {
        method: 'PATCH',
        body: { tags }
      });
      setMessage('Target tags updated.');
      setEditTargetId('');
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not update target tags.'));
    } finally {
      setBusy('');
    }
  }

  async function removeTarget(item: DataItem) {
    if (!canWriteTargets) return;
    const targetId = getString(item, ['id'], '');
    const value = getString(item, ['value'], targetId);
    if (!targetId) return;
    const childCount = subdomainGrouping.childCount.get(targetId) ?? 0;
    const childClause = childCount > 0
      ? ` This also removes the ${childCount} ${childCount === 1 ? 'subdomain' : 'subdomains'} grouped under it.`
      : '';
    if (!await confirm({
      title: 'Remove declared target',
      description: `Remove ${value} from declared scope?${childClause} Existing evidence is retained. Active runs must finish or be cancelled first.`,
      confirmLabel: childCount > 0 ? 'Remove domain and subdomains' : 'Remove target'
    })) return;
    setBusy(`remove-${targetId}`);
    setMessage('');
    setError('');
    try {
      await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}`, { method: 'DELETE' });
      setMessage(`${value} removed from declared scope.`);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not remove the target.'));
    } finally {
      setBusy('');
    }
  }

  /** Refined row model, built from the same helpers and gates as the Classic columns. */
  function describeTarget(item: DataItem): TargetRowModel {
    const id = getString(item, ['id'], '');
    const state = verificationState(item);
    const verification = item.verification && typeof item.verification === 'object' && !Array.isArray(item.verification) ? item.verification as DataItem : null;
    const result = latestRunVerdict(latestRuns.get(id) ?? null);
    return {
      item,
      id,
      value: getString(item, ['value'], id),
      kind: getString(item, ['kind'], 'unknown').toLowerCase(),
      kindLabel: formatTargetKind(getString(item, ['kind'], ''), getString(item, ['value'], '')),
      verified: isVerified(state),
      verificationState: state,
      verificationProvenance: resolveTargetVerificationProvenance(item, verification),
      tags: visibleTargetTags(item),
      source: sourceLabel(item),
      rawSource: getString(item, ['source'], 'manual'),
      createdAt: item.created_at ?? null,
      lastRecorded: item.last_validation_at ?? item.last_validated_at ?? (result?.completedAt || null),
      lastResult: result,
      subdomainCount: subdomainGrouping.childCount.get(id) ?? 0
    };
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const value = getString(item, ['value'], id);
        const verified = isVerified(verificationState(item));
        const childCount = subdomainGrouping.childCount.get(id) ?? 0;
        const tags = visibleTargetTags(item);
        const source = sourceLabel(item).replace(/_/g, ' ');
        return (
          <span className="target-primary">
            <DomainFavicon value={getString(item, ['value'])} kind={getString(item, ['kind'], 'fqdn')} className="target-primary-icon" />
            <span className="target-primary-copy">
              <a
                className="target-primary-name detail-entity-link"
                href={verified ? buildDetailHref('target-detail', id) : `${buildDetailHref('target-detail', id)}&tab=overview`}
                title={`${value} · added from ${source}${item.created_at ? ` on ${formatDate(item.created_at)}` : ''}`}
                data-focus-key={`target-name-${id}`}
                onClick={() => rememberRow(id, `target-name-${id}`)}
              >
                <strong>{value}</strong>
              </a>
              <span className="target-primary-meta">
                <span>{formatTargetKind(getString(item, ['kind'], ''), getString(item, ['value'], ''))}</span>
                {childCount ? <span title={`${childCount} subdomains are grouped under this domain; open it to review them`}>{`· ${childCount} ${childCount === 1 ? 'subdomain' : 'subdomains'}`}</span> : null}
                {tags.length ? (
                  <span className="target-tag-chip" title={tags.join(', ')}>
                    {tags[0]}
                    {tags.length > 1 ? <span className="target-tag-more">{`+${tags.length - 1}`}</span> : null}
                  </span>
                ) : null}
              </span>
            </span>
          </span>
        );
      }
    },
    {
      key: 'verification',
      label: 'Ownership',
      render: (item) => {
        const verification = item.verification && typeof item.verification === 'object' && !Array.isArray(item.verification) ? item.verification as DataItem : null;
        const state = verificationState(item);
        const status = isVerified(state) ? { tone: 'verified', label: 'Verified' }
          : ['pending', 'dns_pending', 'checking'].includes(state.toLowerCase()) ? { tone: 'pending', label: 'Pending' }
            : state.toLowerCase() === 'agent_verified' ? { tone: 'pending', label: 'Re-verify' }
            : { tone: 'unverified', label: 'Not verified' };
        return (
          <span className="target-status" data-tone={status.tone} title={resolveTargetVerificationProvenance(item, verification)}>
            <span className="target-status-dot" aria-hidden="true" />
            {status.label}
          </span>
        );
      }
    },
    {
      key: 'validated',
      label: 'Last result',
      render: (item) => {
        const run = latestRuns.get(getString(item, ['id'], '')) ?? null;
        const result = latestRunVerdict(run);
        const recorded = item.last_validation_at ?? item.last_validated_at ?? (result?.completedAt || null);
        if (!recorded) {
          return <span className="target-unknown">{runsUnavailable ? 'Unavailable' : 'No result yet'}</span>;
        }
        return (
          <span className="target-validation">
            {runsUnavailable ? (
              <Badge tone={EVIDENCE_STATUS_TONE.none} title="Validation runs did not load, so the latest verdict is unknown">Unavailable</Badge>
            ) : (
              <Badge tone={EVIDENCE_STATUS_TONE[result?.status ?? 'none']} title={result?.verdict ? `Latest evidence-backed verdict: ${result.verdict}` : 'No evidence-backed verdict recorded for this target'}>
                {result ? result.label : 'Not recorded'}
              </Badge>
            )}
            <TableDate value={recorded} />
          </span>
        );
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const value = getString(item, ['value'], id);
        const verified = isVerified(verificationState(item));
        const promptVerify = !verified && canWriteTargets;
        const menuActions: RowAction[] = canWriteTargets ? [
          { key: 'tags', label: 'Edit tags', ariaLabel: `Edit tags for ${value}`, icon: <Tags size={14} aria-hidden="true" />, onSelect: () => openTagEditor(item) },
          { key: 'remove', label: 'Remove', ariaLabel: `Remove target ${value}`, icon: <Trash2 size={14} aria-hidden="true" />, tone: 'danger', disabled: busy === `remove-${id}`, onSelect: () => void removeTarget(item) }
        ] : [];
        return (
          <span className="target-row-actions">
            {verified && canRunChecks ? (
              <AnchorButton
                size="sm"
                variant="secondary"
                href={`${buildDetailHref('target-detail', id)}&tab=validate`}
                data-focus-key={`target-validate-${id}`}
                onClick={() => rememberRow(id, `target-validate-${id}`)}
                aria-label={`Validate ${value}`}
              >
                <Play size={13} aria-hidden="true" />Validate
              </AnchorButton>
            ) : null}
            <AnchorButton
              size="sm"
              variant={promptVerify ? 'secondary' : 'ghost'}
              href={verified ? buildDetailHref('target-detail', id) : `${buildDetailHref('target-detail', id)}&tab=overview`}
              data-focus-key={`target-${id}`}
              onClick={() => rememberRow(id)}
              aria-label={promptVerify ? `Verify ownership of ${value}` : `Open target ${value}`}
            >
              {promptVerify ? 'Verify' : 'Open'}
            </AnchorButton>
            <RowActionsMenu label={`More actions for ${value}`} actions={menuActions} />
          </span>
        );
      }
    }
  ];

  return (
    <div className="content targets-page">
      <style>{TARGETS_PAGE_STYLES}</style>
      <div className="page-head">
        <div>
          <h1>Targets</h1>
          <p>Declared hostnames, IPs and endpoints. Each must prove ownership before any bounded check runs.</p>
        </div>
        <div className="row-actions">
          {showVariantSwitch ? <VariantSwitch value={variant} onChange={setVariant} /> : null}
          <TargetCsvImportButton config={config} session={session} onImported={onRefresh} />
          {unverifiedCount > 0 ? <Button variant="secondary" onClick={() => setVerificationFilter('unverified')}>Show unverified</Button> : null}
          {canWriteTargets ? <Button onClick={(event) => (showAdd ? closeAddForm() : openAddForm(event.currentTarget))} aria-expanded={showAdd} aria-controls="target-declare-form"><Plus size={16} /> Add target</Button> : null}
        </div>
      </div>

      {error ? <div className="form-banner error" role="alert">{error}</div> : null}
      {message && !error ? (
        <Toast
          message={message}
          tone="success"
          duration={5000}
          onDismiss={() => setMessage('')}
        />
      ) : null}

      {cohort ? (
        <TargetCohortList filters={cohort} config={config} session={session} inventory={targets} onClear={clearCohort} />
      ) : null}

      {!cohort && variant !== 'refined' ? (<>
      <div className="targets-summary" role="group" aria-label="Target inventory summary">
        <div className="targets-summary-cell"><span>Declared target records</span><strong>{formatNumber(units.records)}</strong><small>Every hostname, IP or endpoint you declared</small></div>
        <div className="targets-summary-cell"><span>Distinct hostnames</span><strong>{formatNumber(units.distinctHosts)}</strong><small>{units.nonHostRecords ? `${formatNumber(units.nonHostRecords)} IP or endpoint records not counted` : 'Normalized host identity'}</small></div>
        <div className="targets-summary-cell"><span>Ownership verified</span><strong>{formatNumber(verifiedCount)}</strong><small>Can be checked after per-check gates</small></div>
        <div className="targets-summary-cell"><span>Ownership pending</span><strong>{formatNumber(unverifiedCount)}</strong><small>Locked: no external check can run</small></div>
      </div>
      </>) : null}

      {canWriteTargets && showAdd ? (
        <Card className="targets-intake">
          <CardHeader>
            <div><CardTitle>Add a target</CardTitle><CardDescription>Declare one target manually. Hostnames and URLs prove ownership with a DNS TXT record; IPs and TCP services are checked as origins of a verified hostname.</CardDescription></div>
            <Button size="sm" variant="ghost" onClick={closeAddForm}>Close</Button>
          </CardHeader>
          <CardContent>
            <form id="target-declare-form" className="targets-intake-form" onSubmit={(event) => void addTarget(event)}>
              <div className="targets-intake-field">
                <label htmlFor="add-target-kind">Kind</label>
                <select id="add-target-kind" ref={kindSelectRef} name="kind" value={addKind} onChange={(event) => setAddKind(event.target.value)} aria-describedby="add-kind-hint">
                  {TARGET_KIND_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                </select>
                <small id="add-kind-hint" className="muted">{addKindOption.hint}</small>
              </div>
              <div className="targets-intake-field">
                <label htmlFor="add-target-value">Value</label>
                <input id="add-target-value" name="value" className="mono" placeholder={addKindOption.placeholder} required aria-describedby="add-value-hint" />
                <small id="add-value-hint" className="muted">Ranges (CIDR) are not supported; declare each IP you own.</small>
              </div>
              <div className="targets-intake-field">
                <label htmlFor="add-target-behavior">Expected behavior</label>
                <select id="add-target-behavior" name="expected_behavior" value={addBehavior} onChange={(event) => setAddBehavior(event.target.value)} aria-describedby="add-behavior-hint">
                  {EXPECTED_BEHAVIOR_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                </select>
                <small id="add-behavior-hint" className="muted">{addBehaviorOption.hint}</small>
              </div>
              <label className="targets-intake-tags">
                <span>Tags</span>
                <input
                  name="tags"
                  className="mono"
                  placeholder="team:payments, tier:edge"
                  value={addTags}
                  onChange={(event) => setAddTags(event.target.value)}
                  aria-invalid={addTagsResult.error ? true : undefined}
                  aria-describedby={addTagsResult.error ? 'add-tags-error' : undefined}
                />
                {addTagsResult.error
                  ? <small id="add-tags-error" className="field-error" role="alert">{addTagsResult.error}</small>
                  : <small className="muted">Comma-separated. {addTagsResult.tags.length}/{MAX_TARGET_TAGS} valid.</small>}
              </label>
              <Button type="submit" loading={busy === 'add'} disabled={Boolean(addTagsResult.error)}><Plus size={15} /> Add target</Button>
            </form>
          </CardContent>
        </Card>
      ) : null}

      {!cohort && variant === 'refined' ? (
        <TargetsRefinedInventory
          config={config}
          session={session}
          loaded={data.loaded}
          loadError={data.loadErrors.targets}
          onRetry={() => void onRefresh()}
          totalCount={topLevelList.length}
          rows={filtered.map(describeTarget)}
          units={units}
          verifiedCount={verifiedCount}
          unverifiedCount={unverifiedCount}
          query={query}
          onQueryChange={setQuery}
          verificationFilter={verificationFilter}
          onVerificationFilterChange={setVerificationFilter}
          kindFilter={kindFilter}
          kindOptions={targetKinds.map((kind) => ({ value: kind, label: formatTargetKind(kind) }))}
          onKindFilterChange={setKindFilter}
          tagFilter={tagFilter}
          tagOptions={allTags}
          onTagFilterChange={setTagFilter}
          filtersActive={filtersActive}
          onClearFilters={clearFilters}
          runsUnavailable={runsUnavailable}
          canWriteTargets={canWriteTargets}
          canRunChecks={canRunChecks}
          busy={busy}
          showAdd={showAdd}
          onAddTarget={openAddForm}
          onEditTags={openTagEditor}
          onRemove={(item) => void removeTarget(item)}
          onRemember={rememberRow}
          detailHref={(id) => buildDetailHref('target-detail', id)}
        />
      ) : null}

      {!cohort && variant !== 'refined' ? (
      <Card>
        <CardHeader>
          <div><CardTitle>Target inventory</CardTitle><CardDescription>{formatNumber(filtered.length)} of {formatNumber(topLevelList.length)} top-level {topLevelList.length === 1 ? 'domain' : 'domains'}. Discovered subdomains are grouped under their parent; open a domain to review them. Verify ownership opens its own DNS record.</CardDescription></div>
        </CardHeader>
        <CardContent>
          <div className="targets-toolbar">
            <label className="targets-search"><Search size={16} aria-hidden="true" /><span className="sr-only">Search targets</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search hostname, tag, provider" /></label>
            <label className="targets-filter"><span>Verification</span><select value={verificationFilter} onChange={(event) => setVerificationFilter(event.target.value)}><option value="all">All states</option><option value="verified">Verified</option><option value="unverified">Not verified</option></select></label>
            <label className="targets-filter"><span>Kind</span><select value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}><option value="all">All kinds</option>{targetKinds.map((kind) => <option key={kind} value={kind}>{formatTargetKind(kind)}</option>)}</select></label>
            <label className="targets-filter"><span>Tag</span><select value={tagFilter} onChange={(event) => setTagFilter(event.target.value)}><option value="all">All tags</option>{allTags.map((tag) => <option key={tag} value={tag}>{tag}</option>)}</select></label>
          </div>
          <p className="targets-result-count" aria-live="polite">
            {formatNumber(filtered.length)} matching {filtered.length === 1 ? 'target record' : 'target records'}
            {filtersActive ? <> · <button type="button" className="link-button" onClick={clearFilters}>Clear filters</button></> : null}
          </p>
          <DataTable
            className="targets-table-wrap"
            columns={columns}
            items={filtered}
            getRowId={(item, index) => getString(item, ['id'], String(index))}
            loadError={data.loadErrors.targets}
            onRetry={() => void onRefresh()}
            empty={
              <EmptyState
                icon={Target}
                title={targets.length ? 'No targets match these filters' : 'No targets declared yet'}
                body={targets.length ? 'The declared inventory is unchanged; only the current filters hide it.' : 'Declare your first hostname, IP or URL. You will get a DNS TXT record to prove ownership; no probe is sent until it is verified.'}
                actionLabel={targets.length ? 'Clear filters' : undefined}
                onAction={targets.length ? clearFilters : undefined}
                actions={!targets.length && canWriteTargets ? (
                  <Button type="button" onClick={(event) => openAddForm(event.currentTarget)} aria-expanded={showAdd} aria-controls="target-declare-form">
                    <Plus size={15} aria-hidden="true" /> Add target
                  </Button>
                ) : undefined}
              />
            }
          />
        </CardContent>
      </Card>
      ) : null}

      <FormModal
        open={canWriteTargets && Boolean(editTargetId)}
        title="Edit target tags"
        description="Trimmed, lowercased, deduplicated. Kind and value stay immutable."
        onClose={() => setEditTargetId('')}
      >
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        <form className="product-form" onSubmit={(event) => void saveTags(event)}>
          <label className="full">
            <span>Tags</span>
            <input
              className="mono"
              placeholder="team:payments, tier:edge"
              value={editTags}
              onChange={(event) => setEditTags(event.target.value)}
              autoFocus
              aria-invalid={editTagsResult.error ? true : undefined}
              aria-describedby={editTagsResult.error ? 'edit-tags-error' : undefined}
            />
            {editTagsResult.error
              ? <small id="edit-tags-error" className="field-error" role="alert">{editTagsResult.error}</small>
              : <small className="muted">Comma-separated. {editTagsResult.tags.length}/{MAX_TARGET_TAGS} valid.</small>}
          </label>
          <div className="form-actions full">
            <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setEditTargetId('')}>Cancel</Button>
            <Button type="submit" loading={busy === `tags-${editTargetId}`} disabled={Boolean(editTagsResult.error)}>Save tags</Button>
          </div>
        </form>
      </FormModal>
    </div>
  );
}
