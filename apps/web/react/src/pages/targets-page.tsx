import { useMemo, useState, type FormEvent } from 'react';
import {
  Cloud,
  CloudSun,
  Globe2,
  Plus,
  Route,
  Search,
  Server,
  ShieldCheck,
  Target,
  Trash2
} from 'lucide-react';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { requestJson } from '../lib/api';
import { buildDetailHref } from '../lib/route-params';
import { formatDate } from '../lib/utils';
import { resolveTargetVerificationProvenance, VerifyChip } from '../lib/verify-chip';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { DataTable, type TableColumn } from '../components/ui/table';
import { EmptyState } from '../components/ui/empty-state';

const TARGETS_PAGE_STYLES = `
.targets-page .targets-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; background: var(--border-soft); gap: 1px; }
.targets-page .targets-summary-cell { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1); padding: var(--space-4); background: var(--surface); }
.targets-page .targets-summary-cell span { color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-summary-cell strong { color: var(--fg); font-family: var(--font-display); font-size: var(--text-xl); font-variant-numeric: tabular-nums; }
.targets-page .targets-intake { border-color: color-mix(in oklab, var(--accent), transparent 70%); }
.targets-page .targets-intake-form { display: grid; grid-template-columns: minmax(200px, 1.15fr) minmax(180px, .85fr) minmax(180px, .85fr) auto; gap: var(--space-3); align-items: end; }
.targets-page .targets-intake-form label { min-width: 0; display: flex; flex-direction: column; gap: var(--space-1-5); color: var(--fg); font-size: var(--text-sm); font-weight: 500; }
.targets-page .targets-intake-form input, .targets-page .targets-intake-form select { width: 100%; min-height: 42px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); padding: 8px 12px; }
.targets-page .targets-toolbar { display: flex; flex-wrap: wrap; align-items: end; gap: var(--space-3); margin-bottom: var(--space-4); }
.targets-page .targets-search { display: flex; min-width: min(100%, 300px); flex: 1 1 280px; align-items: center; gap: var(--space-2); min-height: 42px; border: 1px solid var(--border); border-radius: var(--radius-pill); background: var(--surface); padding: 0 var(--space-3); }
.targets-page .targets-search input { width: 100%; min-width: 0; border: 0; outline: 0; background: transparent; color: var(--fg); }
.targets-page .targets-filter { display: flex; min-width: 160px; flex-direction: column; gap: var(--space-1); color: var(--fg-2); font-size: var(--text-xs); }
.targets-page .targets-filter select { min-height: 42px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--surface); color: var(--fg); padding: 8px 10px; }
.targets-page .target-primary { display: flex; min-width: 220px; align-items: center; gap: var(--space-3); }
.targets-page .target-primary-icon, .targets-page .provider-mark { display: inline-grid; width: 34px; height: 34px; flex: none; place-items: center; border: 1px solid var(--border); border-radius: var(--radius-md); background: color-mix(in oklab, var(--surface), var(--fg) 3%); color: var(--fg-2); }
.targets-page .target-primary-copy, .targets-page .source-cell { display: flex; min-width: 0; flex-direction: column; gap: 2px; }
.targets-page .target-primary-copy strong { max-width: 36ch; overflow: hidden; text-overflow: ellipsis; color: var(--fg); font-family: var(--font-mono); font-size: var(--text-sm); }
.targets-page .target-primary-copy span, .targets-page .source-cell small { color: var(--muted); font-size: var(--text-xs); }
.targets-page .provider-line { display: flex; min-width: 170px; align-items: center; gap: var(--space-2); }
.targets-page .provider-mark { width: 30px; height: 30px; border-radius: var(--radius-pill); }
.targets-page .target-row-actions { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.targets-page .target-row-actions .btn { min-height: 34px; }
@media (min-width: 901px) {
  .targets-page .data-table { width: 100%; table-layout: fixed; }
  .targets-page .data-table th:nth-child(1) { width: 22%; }
  .targets-page .data-table th:nth-child(2) { width: 12%; }
  .targets-page .data-table th:nth-child(3) { width: 13%; }
  .targets-page .data-table th:nth-child(4) { width: 12%; }
  .targets-page .data-table th:nth-child(5) { width: 14%; }
  .targets-page .data-table th:nth-child(6) { width: 9%; }
  .targets-page .data-table th:nth-child(7) { width: 18%; }
  .targets-page .target-primary,
  .targets-page .provider-line { min-width: 0; }
  .targets-page .provider-line { align-items: flex-start; }
  .targets-page .data-table td { min-width: 0; overflow-wrap: anywhere; }
}
@media (min-width: 701px) and (max-width: 900px) {
  .targets-page .targets-table-wrap { overflow-x: visible; }
  .targets-page .targets-table-wrap .data-table,
  .targets-page .targets-table-wrap tbody { display: block; width: 100%; }
  .targets-page .targets-table-wrap thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
  .targets-page .targets-table-wrap tbody { display: grid; gap: var(--space-3); }
  .targets-page .targets-table-wrap tbody tr:not(.table-empty-row) { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-2) var(--space-4); border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface); padding: var(--space-4); }
  .targets-page .targets-table-wrap tbody tr:not(.table-empty-row) td { display: grid; grid-template-columns: minmax(92px, .42fr) minmax(0, 1fr); gap: var(--space-3); align-items: start; min-width: 0; border-bottom: 0; padding: var(--space-1) 0; }
  .targets-page .targets-table-wrap tbody tr:not(.table-empty-row) td::before { content: attr(data-label); color: var(--fg-2); font-size: var(--text-xs); font-weight: 600; }
  .targets-page .targets-table-wrap tbody tr:not(.table-empty-row) td:last-child { grid-column: 1 / -1; }
  .targets-page .target-primary,
  .targets-page .provider-line { min-width: 0; }
  .targets-page .target-row-actions { align-items: center; flex-direction: row; }
  .targets-page .target-row-actions .btn { width: auto; justify-content: center; }
}
@media (max-width: 900px) {
  .targets-page .target-row-actions .btn { min-height: 44px; }
}
@media (min-width: 901px) and (max-width: 1100px) {
  .targets-page .target-row-actions { align-items: stretch; flex-direction: column; }
  .targets-page .target-row-actions .btn { width: 100%; justify-content: center; }
}
@media (max-width: 1000px) { .targets-page .targets-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); } .targets-page .targets-intake-form { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 620px) { .targets-page .targets-summary, .targets-page .targets-intake-form { grid-template-columns: 1fr; } .targets-page .targets-filter { flex: 1 1 100%; } .targets-page .targets-intake-form .btn { width: 100%; } }
`;

type Tone = NonNullable<BadgeProps['tone']>;

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
  return ['dns_verified', 'agent_verified', 'user_confirmed', 'verified'].includes(state.trim().toLowerCase());
}

function eligibilityTone(value: string): Tone {
  const key = value.trim().toLowerCase();
  if (key === 'eligible' || key === 'ready') return 'success';
  if (key.startsWith('not') || key === 'ineligible') return 'warn';
  return 'muted';
}

function sourceLabel(item: DataItem) {
  const metadata = item.metadata && typeof item.metadata === 'object' && !Array.isArray(item.metadata)
    ? item.metadata as DataItem
    : null;
  const integration = getString(item, ['import_integration', 'import_source'], '');
  if (integration && integration !== '—') return integration;
  return getString(metadata, ['source_app', 'app', 'source'], getString(item, ['source'], 'manual'));
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
  const [query, setQuery] = useState('');
  const [verificationFilter, setVerificationFilter] = useState('all');
  const [eligibilityFilter, setEligibilityFilter] = useState('all');
  const [showAdd, setShowAdd] = useState(false);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const targets = Array.isArray(data.targets) ? data.targets : [];
  const groups = Array.isArray(data.targetGroups) ? data.targetGroups : [];

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return targets.filter((item) => {
      const state = verificationState(item).toLowerCase();
      const eligibility = getString(item, ['eligibility'], 'unknown').toLowerCase();
      if (verificationFilter === 'verified' && !isVerified(state)) return false;
      if (verificationFilter === 'unverified' && isVerified(state)) return false;
      if (eligibilityFilter !== 'all' && eligibility !== eligibilityFilter) return false;
      if (!needle) return true;
      return [
        getString(item, ['value'], ''),
        getString(item, ['target_group_name', 'target_group_id'], ''),
        getString(item, ['environment_name', 'environment_id'], ''),
        sourceLabel(item)
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [targets, query, verificationFilter, eligibilityFilter]);

  const verifiedCount = targets.filter((item) => isVerified(verificationState(item))).length;
  const eligibleCount = targets.filter((item) => getString(item, ['eligibility'], '').toLowerCase() === 'eligible').length;
  const integrationCount = new Set(
    targets.map(sourceLabel).filter((source) => !['manual', 'astranull portal', '—'].includes(source.toLowerCase()))
  ).size;

  async function addDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const groupId = String(form.get('target_group_id') ?? '').trim();
    const value = String(form.get('value') ?? '').trim().toLowerCase().replace(/\.$/, '');
    const expectedBehavior = String(form.get('expected_behavior') ?? 'block_at_edge');
    if (!groupId || !value) return;
    setBusy('add');
    setMessage('');
    setError('');
    try {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(groupId)}/targets`, {
        method: 'POST',
        body: {
          kind: 'fqdn',
          value,
          expected_behavior: expectedBehavior,
          metadata: { source: 'manual', source_app: 'AstraNull portal' }
        }
      });
      setMessage(`${value} added to declared scope. Verify ownership before running checks.`);
      setShowAdd(false);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not add the domain.');
    } finally {
      setBusy('');
    }
  }

  async function removeTarget(item: DataItem) {
    const targetId = getString(item, ['id'], '');
    const groupId = getString(item, ['target_group_id'], '');
    const value = getString(item, ['value'], targetId);
    if (!targetId || !groupId) return;
    if (!window.confirm(`Remove ${value} from declared scope? Existing evidence is retained. Active runs must finish or be cancelled first.`)) return;
    setBusy(`remove-${targetId}`);
    setMessage('');
    setError('');
    try {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(groupId)}/targets/${encodeURIComponent(targetId)}`, { method: 'DELETE' });
      setMessage(`${value} removed from declared scope.`);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove the target.');
    } finally {
      setBusy('');
    }
  }

  const columns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => (
        <span className="target-primary">
          <span className="target-primary-icon" aria-hidden="true">{getString(item, ['kind'], 'fqdn') === 'ip' ? <Server size={16} /> : <Globe2 size={16} />}</span>
          <span className="target-primary-copy">
            <strong title={getString(item, ['value'], '')}>{getString(item, ['value'], '—')}</strong>
            <span>{getString(item, ['kind'], 'unknown')} · {getString(item, ['environment_name', 'environment_id'], 'Unassigned environment')}</span>
          </span>
        </span>
      )
    },
    {
      key: 'group',
      label: 'Target group',
      render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', getString(item, ['target_group_id'], ''))}>{getString(item, ['target_group_name', 'target_group_id'], '—')}</AnchorButton>
    },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => {
        const verification = item.verification && typeof item.verification === 'object' && !Array.isArray(item.verification) ? item.verification as DataItem : null;
        return <VerifyChip state={verificationState(item)} provenance={resolveTargetVerificationProvenance(item, verification)} />;
      }
    },
    {
      key: 'eligibility',
      label: 'Test eligibility',
      render: (item) => {
        const eligibility = getString(item, ['eligibility'], 'unknown');
        const reason = getString(item, ['eligibility_reason'], '');
        return (
          <span className="source-cell">
            <Badge tone={eligibilityTone(eligibility)} title={reason || `Eligibility ${eligibility}`}>{eligibility.replace(/_/g, ' ')}</Badge>
            {reason && reason !== '—' ? <small>{reason.replace(/_/g, ' ')}</small> : null}
          </span>
        );
      }
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
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <span className="target-row-actions">
            <AnchorButton
              size="sm"
              variant="ghost"
              href={buildDetailHref('target-detail', id)}
              aria-label={`Open target ${getString(item, ['value'], id)}`}
            >
              Open target
            </AnchorButton>
            <Button size="sm" variant="danger" loading={busy === `remove-${id}`} onClick={() => void removeTarget(item)} aria-label={`Remove ${getString(item, ['value'], id)}`}><Trash2 size={13} /> Remove</Button>
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
          <p className="eyebrow">Declared scope</p>
          <h1>Targets</h1>
          <p>Every configured hostname and IP, with ownership provenance, test eligibility, source integration, and group policy context.</p>
        </div>
        <Button onClick={() => setShowAdd((current) => !current)}><Plus size={16} /> Add single domain</Button>
      </div>

      {message ? <div className="form-banner" role="status">{message}</div> : null}
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}

      <div className="targets-summary" aria-label="Target inventory summary">
        <div className="targets-summary-cell"><span>Configured targets</span><strong>{targets.length}</strong></div>
        <div className="targets-summary-cell"><span>Ownership verified</span><strong>{verifiedCount}</strong></div>
        <div className="targets-summary-cell"><span>Eligible for tests</span><strong>{eligibleCount}</strong></div>
        <div className="targets-summary-cell"><span>Import integrations represented</span><strong>{integrationCount}</strong></div>
      </div>

      {showAdd ? (
        <Card className="targets-intake">
          <CardHeader>
            <div><CardTitle>Add a single domain</CardTitle><CardDescription>Declare one hostname manually. DNS or agent verification is still required before any probe can run.</CardDescription></div>
            <Button size="sm" variant="ghost" onClick={() => setShowAdd(false)}>Close</Button>
          </CardHeader>
          <CardContent>
            <form className="targets-intake-form" onSubmit={(event) => void addDomain(event)}>
              <label><span>Domain</span><input name="value" className="mono" placeholder="api.example.com" required /></label>
              <label><span>Target group</span><select name="target_group_id" required defaultValue=""><option value="" disabled>Select group</option>{groups.map((group) => <option key={getString(group, ['id'], '')} value={getString(group, ['id'], '')}>{getString(group, ['name', 'id'], 'Unnamed group')}</option>)}</select></label>
              <label><span>Expected behavior</span><select name="expected_behavior" defaultValue="block_at_edge"><option value="block_at_edge">Block at edge</option><option value="absorb_at_origin">Absorb at origin</option><option value="rate_shape">Rate shape</option></select></label>
              <Button type="submit" loading={busy === 'add'} disabled={groups.length === 0}><Plus size={15} /> Add domain</Button>
            </form>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <div><CardTitle>Target inventory</CardTitle><CardDescription>{filtered.length} of {targets.length} configured targets. Use Open target for evidence-backed detail; other row actions remain independent.</CardDescription></div>
        </CardHeader>
        <CardContent>
          <div className="targets-toolbar">
            <label className="targets-search"><Search size={16} aria-hidden="true" /><span className="sr-only">Search targets</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search hostname, group, environment, or provider" /></label>
            <label className="targets-filter"><span>Verification</span><select value={verificationFilter} onChange={(event) => setVerificationFilter(event.target.value)}><option value="all">All states</option><option value="verified">Verified</option><option value="unverified">Not verified</option></select></label>
            <label className="targets-filter"><span>Eligibility</span><select value={eligibilityFilter} onChange={(event) => setEligibilityFilter(event.target.value)}><option value="all">All targets</option><option value="eligible">Eligible</option><option value="not_eligible">Not eligible</option></select></label>
          </div>
          <DataTable
            className="targets-table-wrap"
            columns={columns}
            items={filtered}
            getRowId={(item, index) => getString(item, ['id'], String(index))}
            loadError={data.loadErrors.targets}
            onRetry={() => void onRefresh()}
            empty={<EmptyState icon={Target} title={targets.length ? 'No targets match these filters' : 'No targets configured yet'} body={targets.length ? 'Clear or adjust the filters to return to the full declared inventory.' : 'Add a single domain here, or import approved provider inventory into a target group.'} actionLabel={targets.length ? undefined : 'Add single domain'} onAction={targets.length ? undefined : () => setShowAdd(true)} />}
          />
        </CardContent>
      </Card>

      <div className="callout info">
        <span className="callout-icon" aria-hidden="true"><ShieldCheck size={17} /></span>
        <div className="callout-body"><p className="callout-title">Declared inventory is not automatic discovery</p><p className="callout-desc">Targets appear only when a customer adds them, imports explicitly selected provider records, or approves an external candidate. Test eligibility remains tied to ownership evidence and safety policy.</p></div>
      </div>
    </div>
  );
}
