import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  Cloud,
  CloudSun,
  Globe2,
  Plus,
  Route,
  Search,
  Server,
  Target,
  Trash2
} from 'lucide-react';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { requestJson } from '../lib/api';
import { apiErrorMessage } from '../lib/error-messages';
import { sessionHasPermission } from '../lib/dataset-access.mjs';
import { buildDetailHref, getRouteParam, replaceRouteParams } from '../lib/route-params';
import { formatDate, formatNumber } from '../lib/utils';
import { resolveTargetVerificationProvenance, VerifyChip } from '../lib/verify-chip';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { DataTable, type TableColumn } from '../components/ui/table';
import { EmptyState } from '../components/ui/empty-state';
import { FormModal, useConfirmModal } from '../lib/crud-ui';
import { canonicalCohortFilters, COHORT_FILTER_KEYS, inventoryUnits } from '../lib/domain-checks.mjs';
import { TargetCohortList } from '../components/targets/target-cohort';
import { useListReturnState, useRestoreListPosition } from '../components/evidence/use-inspector';

const TARGETS_PAGE_STYLES = `
.targets-page .targets-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; background: var(--border-soft); gap: 1px; }
.targets-page .targets-summary-cell { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1); padding: var(--space-4); background: var(--surface); }
.targets-page .targets-summary-cell span { color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-summary-cell small { color: var(--fg-2); font-size: var(--text-xs); line-height: 1.4; }
.targets-page .target-primary-actions { display: flex; flex-wrap: wrap; gap: var(--space-2); margin-top: var(--space-2); }
.targets-page .target-unknown { color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-summary-cell strong { color: var(--fg); font-family: var(--font-display); font-size: var(--text-xl); font-variant-numeric: tabular-nums; }
.targets-page .targets-intake { border-color: color-mix(in oklab, var(--accent), transparent 70%); }
.targets-page .targets-intake-form { display: grid; grid-template-columns: minmax(200px, 1.15fr) minmax(180px, .85fr) minmax(180px, .85fr) auto; gap: var(--space-3); align-items: end; }
.targets-page .targets-intake-form label { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1-5); color: var(--fg); font-size: var(--text-sm); font-weight: 500; }
.targets-page .targets-intake-form input, .targets-page .targets-intake-form select { width: 100%; min-height: 42px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); padding: 8px 12px; }
.targets-page .targets-toolbar { display: grid; grid-template-columns: minmax(240px, 1.5fr) repeat(4, minmax(150px, 1fr)); align-items: end; gap: var(--space-3); margin-bottom: var(--space-3); }
.targets-page .targets-search { display: flex; min-width: 0; align-items: center; gap: var(--space-2); min-height: 44px; border: 1px solid var(--border); border-radius: var(--radius-pill); background: var(--surface-sunk); padding: 0 var(--space-3); }
.targets-page .targets-search input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fg); }
.targets-page .targets-filter { display: flex; min-width: 0; flex-direction: column; gap: var(--space-1); color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-filter select { width: 100%; min-height: 44px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface-sunk); color: var(--fg); padding: 8px 10px; }
.targets-page .targets-result-count { margin: 0 0 var(--space-3); color: var(--fg-2); font-family: var(--font-mono); font-size: var(--text-xs); }
.targets-page .target-primary { display: flex; min-width: 220px; align-items: center; gap: var(--space-3); }
.targets-page .target-primary-icon, .targets-page .provider-mark { display: inline-grid; width: 34px; height: 34px; flex: none; place-items: center; border: 1px solid var(--border); border-radius: var(--radius-md); background: color-mix(in oklab, var(--surface), var(--fg) 3%); color: var(--fg-2); }
.targets-page .target-primary-copy, .targets-page .source-cell { display: flex; min-width: 0; flex-direction: column; gap: 2px; }
.targets-page a.target-primary-copy { border-radius: var(--radius-sm); color: inherit; text-decoration: none; }
.targets-page a.target-primary-copy:hover strong { color: var(--accent); }
.targets-page a.target-primary-copy:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.targets-page .target-primary-copy strong { max-width: 36ch; overflow: hidden; text-overflow: ellipsis; color: var(--fg); font-family: var(--font-mono); font-size: var(--text-sm); }
.targets-page .target-primary-copy span, .targets-page .source-cell small { color: var(--muted); font-size: var(--text-xs); }
.targets-page .provider-line { display: flex; min-width: 170px; align-items: center; gap: var(--space-2); }
.targets-page .provider-mark { width: 30px; height: 30px; border-radius: var(--radius-pill); }
/* Actions stay on one line; the table scrolls horizontally inside its region instead of stacking buttons into tall rows. */
.targets-page .target-row-actions { display: flex; flex-wrap: nowrap; gap: var(--space-2); width: max-content; }
.targets-page .target-tag-chips { display: flex; flex-wrap: wrap; gap: var(--space-1-5); }
.targets-page .targets-intake-tags { grid-column: 1 / -1; }
.targets-page .field-error { color: var(--danger); font-size: var(--text-xs); }
.targets-page .target-row-actions .btn { min-height: 34px; }
.targets-page .targets-table-wrap .data-table { min-width: 1180px; }
@media (max-width: 1120px) { .targets-page .targets-toolbar { grid-template-columns: repeat(2, minmax(0, 1fr)); } .targets-page .targets-search { grid-column: 1 / -1; } }
@media (max-width: 900px) {
  .targets-page .target-row-actions .btn { min-height: 44px; }
}
@media (max-width: 1000px) { .targets-page .targets-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } .targets-page .targets-intake-form { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 620px) { .targets-page .targets-intake-form, .targets-page .targets-toolbar { grid-template-columns: 1fr; } .targets-page .targets-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } .targets-page .targets-summary-cell { padding: var(--space-3); } .targets-page .targets-summary-cell small { display: none; } .targets-page .targets-search { grid-column: auto; } .targets-page .targets-intake-form .btn { width: 100%; } }
`;

type Tone = NonNullable<BadgeProps['tone']>;

/** ADR-0008 target kinds accepted by POST /v1/targets (src/contracts/targetManagement.mjs). */
const TARGET_KIND_OPTIONS: { value: string; label: string }[] = [
  { value: 'fqdn', label: 'FQDN / hostname' },
  { value: 'ip', label: 'IP address' },
  { value: 'url', label: 'URL' },
  { value: 'tcp', label: 'TCP host:port' },
  { value: 'dns_zone', label: 'DNS zone' },
  { value: 'canary', label: 'Canary endpoint' }
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

function targetKindLabel(item: DataItem) {
  const kind = getString(item, ['kind'], 'unknown').toLowerCase();
  const value = getString(item, ['value'], '');
  if (kind === 'fqdn' || kind === 'hostname' || kind === 'domain') return 'Hostname';
  if (kind === 'ip') return value.includes(':') ? 'IPv6' : 'IPv4';
  if (kind === 'cidr') return 'CIDR';
  return kind.replace(/_/g, ' ');
}

function providerKey(value: string) {
  const key = value.trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (key.includes('cloudflare')) return 'cloudflare';
  if (key.includes('route53') || key.includes('route_53')) return 'route53';
  if (key.includes('godaddy')) return 'godaddy';
  if (key.includes('namecheap')) return 'namecheap';
  if (key.includes('hetzner') || key === 'hdns') return 'hetzner_dns';
  if (key.includes('google') || key === 'gcp') return 'gcp';
  if (key.includes('azure')) return 'azure';
  if (key.includes('aws')) return 'aws';
  return key || 'manual';
}

function ProviderIcon({ source }: { source: string }) {
  const key = providerKey(source);
  const Icon = key === 'cloudflare'
    ? CloudSun
    : key === 'route53'
      ? Route
      : key === 'hetzner_dns'
        ? Server
        : ['gcp', 'azure', 'aws'].includes(key)
          ? Cloud
          : key === 'manual'
            ? Target
            : Globe2;
  return <span className="provider-mark" aria-hidden="true"><Icon size={15} /></span>;
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
  const { initial, save } = useListReturnState(session, 'targets');
  const urlVerification = getRouteParam('verification');
  const savedFilters: Record<string, string> = { ...(initial.filters ?? {}), ...(urlVerification ? { verification: urlVerification } : {}) };
  const [cohort, setCohort] = useState<Record<string, string> | null>(readCohortFromAddress);
  useEffect(() => {
    const sync = () => setCohort(readCohortFromAddress());
    window.addEventListener('hashchange', sync);
    window.addEventListener('popstate', sync);
    return () => {
      window.removeEventListener('hashchange', sync);
      window.removeEventListener('popstate', sync);
    };
  }, []);
  const [query, setQuery] = useState(savedFilters.q ?? '');
  const [verificationFilter, setVerificationFilter] = useState(savedFilters.verification ?? 'all');
  const [groupFilter, setGroupFilter] = useState(savedFilters.group ?? 'all');
  const [kindFilter, setKindFilter] = useState(savedFilters.kind ?? 'all');
  const [tagFilter, setTagFilter] = useState(savedFilters.tag ?? 'all');
  const [showAdd, setShowAdd] = useState(false);
  const [addKind, setAddKind] = useState('fqdn');
  const [addTags, setAddTags] = useState('');
  const [editTargetId, setEditTargetId] = useState('');
  const [editTags, setEditTags] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const canWriteTargets = sessionHasPermission(session, 'target_group:write');
  const targets = Array.isArray(data.targets) ? data.targets : [];
  const groups = Array.isArray(data.targetGroups) ? data.targetGroups : [];
  const addTagsResult = parseTagInput(addTags);
  const editTagsResult = parseTagInput(editTags);
  const allTags = useMemo(
    () => [...new Set(targets.flatMap((item) => targetTags(item)))].sort(),
    [targets]
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return targets.filter((item) => {
      const state = verificationState(item).toLowerCase();
      if (verificationFilter === 'verified' && !isVerified(state)) return false;
      if (verificationFilter === 'unverified' && isVerified(state)) return false;
      const groupId = getString(item, ['target_group_id'], '');
      const kind = getString(item, ['kind'], 'unknown').toLowerCase();
      if (groupFilter !== 'all' && groupId !== groupFilter) return false;
      if (kindFilter !== 'all' && kind !== kindFilter) return false;
      if (tagFilter !== 'all' && !targetTags(item).includes(tagFilter)) return false;
      if (!needle) return true;
      return [
        getString(item, ['value'], ''),
        getString(item, ['target_group_name', 'target_group_id'], ''),
        targetTags(item).join(' '),
        sourceLabel(item)
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [targets, query, verificationFilter, groupFilter, kindFilter, tagFilter]);

  const verifiedCount = targets.filter((item) => isVerified(verificationState(item))).length;
  const unverifiedCount = targets.length - verifiedCount;
  const units = useMemo(() => inventoryUnits(targets), [targets]);
  const filtersActive = Boolean(query.trim()) || verificationFilter !== 'all' || groupFilter !== 'all' || kindFilter !== 'all' || tagFilter !== 'all';

  function clearCohort() {
    replaceRouteParams(Object.fromEntries(COHORT_ADDRESS_KEYS.map((key) => [key, null])));
    setCohort(null);
  }

  useEffect(() => {
    save({ filters: { q: query.trim(), verification: verificationFilter, group: groupFilter, kind: kindFilter, tag: tagFilter } });
  }, [save, query, verificationFilter, groupFilter, kindFilter, tagFilter]);
  useRestoreListPosition(data.loaded && filtered.length > 0, initial);

  function clearFilters() {
    setQuery('');
    setVerificationFilter('all');
    setGroupFilter('all');
    setKindFilter('all');
    setTagFilter('all');
  }

  function rememberRow(id: string) {
    save({ selectedRowId: id, focusKey: `target-${id}` });
  }
  const targetKinds = [...new Set(targets.map((item) => getString(item, ['kind'], 'unknown').toLowerCase()).filter(Boolean))].sort();

  async function addTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteTargets) return;
    const form = new FormData(event.currentTarget);
    const value = String(form.get('value') ?? '').trim();
    const expectedBehavior = String(form.get('expected_behavior') ?? 'block_at_edge');
    const groupId = String(form.get('target_group_id') ?? '').trim();
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
        expected_behavior: expectedBehavior,
        tags
      };
      if (groupId) body.target_group_id = groupId;
      const created = await requestJson(config, session, '/v1/targets', { method: 'POST', body }) as DataItem;
      const createdId = getString(created, ['id'], '');
      const createdGroupId = getString(created, ['target_group_id'], groupId);
      // Onboarding: issue the DNS TXT ownership challenge straight away so the target page can
      // show the record, keep re-checking it, and start WAF/CDN detection once it verifies.
      if (createdId && createdGroupId && addKind === 'fqdn') {
        await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(createdGroupId)}/dns-ownership/issue`, {
          method: 'POST',
          body: { target_id: createdId }
        }).catch(() => undefined);
      }
      setMessage(`${value} added to declared scope. Verify ownership before running checks.`);
      save({ selectedRowId: createdId, focusKey: createdId ? `target-${createdId}` : undefined });
      setShowAdd(false);
      setAddTags('');
      setAddKind('fqdn');
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
    const groupId = getString(item, ['target_group_id'], '');
    const value = getString(item, ['value'], targetId);
    if (!targetId || !groupId) return;
    if (!await confirm({
      title: 'Remove declared target',
      description: `Remove ${value} from declared scope? Existing evidence is retained. Active runs must finish or be cancelled first.`,
      confirmLabel: 'Remove target'
    })) return;
    setBusy(`remove-${targetId}`);
    setMessage('');
    setError('');
    try {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(groupId)}/targets/${encodeURIComponent(targetId)}`, { method: 'DELETE' });
      setMessage(`${value} removed from declared scope.`);
      await onRefresh();
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not remove the target.'));
    } finally {
      setBusy('');
    }
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const value = getString(item, ['value'], id);
        const verified = isVerified(verificationState(item));
        return (
          <span className="target-primary">
            <span className="target-primary-icon" aria-hidden="true">{getString(item, ['kind'], 'fqdn') === 'ip' ? <Server size={16} /> : <Globe2 size={16} />}</span>
            <span className="target-primary-copy">
              <strong title={value}>{value}</strong>
              <span>{targetKindLabel(item)}</span>
              <span className="target-primary-actions">
                <AnchorButton
                  size="sm"
                  variant={verified ? 'secondary' : 'default'}
                  href={verified ? buildDetailHref('target-detail', id) : `${buildDetailHref('target-detail', id)}&tab=overview`}
                  data-focus-key={`target-${id}`}
                  onClick={() => rememberRow(id)}
                  aria-label={verified ? `Open target ${value}` : `Verify ownership of ${value}`}
                >
                  {verified ? 'Open' : 'Verify ownership'}
                </AnchorButton>
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
        return <VerifyChip state={verificationState(item)} provenance={resolveTargetVerificationProvenance(item, verification)} />;
      }
    },
    {
      key: 'validated',
      label: 'Last validation',
      render: (item) => {
        if (!Object.hasOwn(item, 'last_validation_at') && !Object.hasOwn(item, 'last_validated_at')) {
          return <span className="target-unknown">Not available in inventory</span>;
        }
        const value = item.last_validation_at ?? item.last_validated_at;
        return value ? <span className="mono small">{formatDate(value)}</span> : <span className="target-unknown">Not checked</span>;
      }
    },
    {
      key: 'tags',
      label: 'Tags',
      render: (item) => {
        const tags = targetTags(item);
        if (tags.length === 0) return <span className="muted">—</span>;
        return (
          <span className="target-tag-chips">
            {tags.map((tag) => <Badge key={tag} tone="info">{tag}</Badge>)}
          </span>
        );
      }
    },
    {
      key: 'group',
      label: 'Target group',
      render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', getString(item, ['target_group_id'], ''))}>{getString(item, ['target_group_name', 'target_group_id'], '—')}</AnchorButton>
    },
    {
      key: 'source',
      label: 'Added from',
      render: (item) => {
        const source = sourceLabel(item);
        return <span className="provider-line"><ProviderIcon source={source} /><span className="source-cell"><strong>{source.replace(/_/g, ' ')}</strong><small>{getString(item, ['source'], 'manual')}</small></span></span>;
      }
    },
    { key: 'added', label: 'Added', render: (item) => <span className="mono small">{formatDate(item.created_at)}</span> },
    {
      key: 'actions',
      label: 'Manage',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <span className="target-row-actions">
            {!canWriteTargets ? <span className="target-unknown">No changes for your role</span> : null}
            {canWriteTargets ? <Button size="sm" variant="secondary" onClick={() => openTagEditor(item)} aria-label={`Edit tags for ${getString(item, ['value'], id)}`}>Edit tags</Button> : null}
            {canWriteTargets ? <Button size="sm" variant="danger" loading={busy === `remove-${id}`} onClick={() => void removeTarget(item)} aria-label={`Remove target ${getString(item, ['value'], id)}`}><Trash2 size={13} /> Remove</Button> : null}
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
          <p className="eyebrow">Proof for customer-declared scope</p>
          <h1>Targets</h1>
          <p>Declared hostnames, IPs and CIDRs. Each must prove ownership before any bounded check runs.</p>
        </div>
        <div className="row-actions">
          <Button variant="secondary" onClick={() => setVerificationFilter('unverified')}>Review unverified</Button>
          {canWriteTargets ? <Button onClick={() => setShowAdd((current) => !current)} aria-expanded={showAdd} aria-controls="target-declare-form"><Plus size={16} /> Add target</Button> : null}
        </div>
      </div>

      {message ? <div className="form-banner" role="status">{message}</div> : null}
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}

      {cohort ? (
        <TargetCohortList filters={cohort} config={config} session={session} inventory={targets} onClear={clearCohort} />
      ) : null}

      {!cohort ? (<>
      <div className="targets-summary" aria-label="Target inventory summary">
        <div className="targets-summary-cell"><span>Declared target records</span><strong>{formatNumber(units.records)}</strong><small>Every hostname, IP, CIDR or endpoint you declared</small></div>
        <div className="targets-summary-cell"><span>Distinct hostnames</span><strong>{formatNumber(units.distinctHosts)}</strong><small>{units.nonHostRecords ? `${formatNumber(units.nonHostRecords)} IP, CIDR or endpoint records not counted` : 'Normalized host identity'}</small></div>
        <div className="targets-summary-cell"><span>Ownership verified</span><strong>{formatNumber(verifiedCount)}</strong><small>Can be checked after per-check gates</small></div>
        <div className="targets-summary-cell"><span>Ownership pending</span><strong>{formatNumber(unverifiedCount)}</strong><small>Locked: no external check can run</small></div>
      </div>
      </>) : null}

      {canWriteTargets && showAdd ? (
        <Card className="targets-intake">
          <CardHeader>
            <div><CardTitle>Add a target</CardTitle><CardDescription>Declare one target manually. Exact-target DNS verification is required before any external probe can run. Omit the group to land in the tenant default group.</CardDescription></div>
            <Button size="sm" variant="ghost" onClick={() => setShowAdd(false)}>Close</Button>
          </CardHeader>
          <CardContent>
            <form id="target-declare-form" className="targets-intake-form" onSubmit={(event) => void addTarget(event)}>
              <label>
                <span>Kind</span>
                <select name="kind" value={addKind} onChange={(event) => setAddKind(event.target.value)}>
                  {TARGET_KIND_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                </select>
              </label>
              <label><span>Value</span><input name="value" className="mono" placeholder="api.example.com" required /></label>
              <label><span>Expected behavior</span><select name="expected_behavior" defaultValue="block_at_edge"><option value="block_at_edge">Block at edge</option><option value="absorb_at_origin">Absorb at origin</option><option value="rate_shape">Rate shape</option></select></label>
              <label>
                <span>Target group</span>
                <select name="target_group_id" defaultValue="">
                  <option value="">Default (auto)</option>
                  {groups.map((group) => <option key={getString(group, ['id'], '')} value={getString(group, ['id'], '')}>{getString(group, ['name', 'id'], 'Unnamed group')}</option>)}
                </select>
              </label>
              <label className="targets-intake-tags">
                <span>Tags</span>
                <input
                  name="tags"
                  className="mono"
                  placeholder="env:prod, tier:edge"
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

      {!cohort ? (
      <Card>
        <CardHeader>
          <div><CardTitle>Target inventory</CardTitle><CardDescription>{formatNumber(filtered.length)} of {formatNumber(targets.length)} loaded target records. Open a target for its profile and checks; Verify ownership opens its own DNS record.</CardDescription></div>
        </CardHeader>
        <CardContent>
          <div className="targets-toolbar">
            <label className="targets-search"><Search size={16} aria-hidden="true" /><span className="sr-only">Search targets</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search hostname, group, tag, or provider" /></label>
            <label className="targets-filter"><span>Verification</span><select value={verificationFilter} onChange={(event) => setVerificationFilter(event.target.value)}><option value="all">All states</option><option value="verified">Verified</option><option value="unverified">Not verified</option></select></label>
            <label className="targets-filter"><span>Target group</span><select value={groupFilter} onChange={(event) => setGroupFilter(event.target.value)}><option value="all">All groups</option>{groups.flatMap((group) => { const id = getString(group, ['id'], ''); return id ? [<option key={id} value={id}>{getString(group, ['name', 'id'], id)}</option>] : []; })}</select></label>
            <label className="targets-filter"><span>Kind</span><select value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}><option value="all">All kinds</option>{targetKinds.map((kind) => <option key={kind} value={kind}>{targetKindLabel({ kind })}</option>)}</select></label>
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
            empty={<EmptyState icon={Target} title={targets.length ? 'No targets match these filters' : 'No targets declared yet'} body={targets.length ? 'The declared inventory is unchanged; only the current filters hide it.' : 'Add a target here, or import approved provider inventory into a target group.'} actionLabel={targets.length ? 'Clear filters' : canWriteTargets ? 'Add target' : undefined} onAction={targets.length ? clearFilters : canWriteTargets ? () => setShowAdd(true) : undefined} />}
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
              placeholder="env:prod, tier:edge"
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
