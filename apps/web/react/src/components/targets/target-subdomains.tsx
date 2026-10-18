import { useEffect, useMemo, useRef, useState } from 'react';
import { Network, RefreshCw } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref } from '../../lib/route-params';
import { formatDate } from '../../lib/utils';
import { providerName } from '../../lib/domain-checks.mjs';
import { ConfirmModal } from '../../lib/crud-ui';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { DataTable, type TableColumn } from '../ui/table';
import { EmptyState } from '../ui/empty-state';

const text = (value: unknown) => typeof value === 'string' ? value : '';
const record = (value: unknown): DataItem => value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : {};
const rows = (value: unknown): DataItem[] => Array.isArray(value) ? value.map(record) : [];
const OBSERVATIONS: Record<string, string> = {
  waf_detected: 'WAF fingerprint observed', cdn_only: 'CDN observed', no_edge_detected: 'No edge fingerprint matched',
  inconclusive: 'Inconclusive', not_checked: 'Not checked',
};
const SOURCE_LABELS: Record<string, string> = { virustotal: 'VirusTotal', virustotal_ui: 'VirusTotal', crtsh: 'Certificate Transparency logs (crt.sh)' };
const NOT_CONFIGURED: Record<string, string> = {
  disabled: 'Subdomain discovery is unavailable. You can declare child hostnames manually.',
  virustotal_api_key_missing: 'Subdomain discovery is unavailable. You can declare child hostnames manually.',
  invalid_source: 'Subdomain discovery is unavailable. You can declare child hostnames manually.',
};
const NOT_CONFIGURED_FALLBACK = 'Subdomain discovery is unavailable. You can declare child hostnames manually.';

function subdomainSourceErrorMessage(code: string, label: string): string {
  const source = label || 'The passive source';
  switch (code) {
    case 'subdomain_source_not_configured': return `${NOT_CONFIGURED_FALLBACK} No hosts were added.`;
    case 'subdomain_source_unreachable': return `${source} could not be reached, so no hosts were added. Try again later.`;
    case 'subdomain_source_failed': return `${source} returned an error, so no hosts were added. Try again in a few minutes, or declare child hostnames manually.`;
    case 'subdomain_source_rate_limited':
    case 'subdomain_source_auth_failed':
    case 'subdomain_source_response_too_large': return `Subdomain discovery could not be completed, so no hosts were added. Try again later, or declare child hostnames manually.`;
    default: return '';
  }
}

function enumerateSummary(result: DataItem, label: string, domain: string): string {
  const created = rows(result.created).length;
  const failed = rows(result.failed).length;
  const found = Number(result.found) || 0;
  const partial = result.truncated ? ' Discovery is incomplete; you can try again later.' : '';
  if (found === 0) return `Added 0 subdomains. ${label || 'The passive source'} returned no hostnames under ${domain}.${partial} Declare child hostnames manually if you know of any.`;
  return `Added ${created} subdomains from ${found} found by ${label || 'the passive source'}; ${Number(result.already_declared) || 0} already declared; ${failed} could not be added.${partial}${created ? ' Initial WAF/CDN detection is queued automatically. Open any host to run its full target checks.' : ''}`;
}

export function TargetSubdomains({ target, config, session, canWrite, canStart }: {
  target: DataItem; config: PortalConfig; session: Session; canWrite: boolean; canStart: boolean;
}) {
  const targetId = text(target.id);
  const parentId = (Array.isArray(target.tags) ? target.tags : []).map(text)
    .find((tag) => tag.startsWith('subdomain-of:'))?.slice('subdomain-of:'.length) ?? '';
  const path = `/v1/targets/${encodeURIComponent(targetId)}/subdomains`;
  const [inventory, setInventory] = useState<DataItem | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [filter, setFilter] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState<'enumerate' | 'detect' | null>(null);
  const [pending, setPending] = useState<string[]>([]);
  const mutation = useRef<AbortController | null>(null);

  useEffect(() => () => mutation.current?.abort(), []);
  useEffect(() => {
    if (parentId || target.kind !== 'fqdn') return undefined;
    const controller = new AbortController();
    let timer: number | undefined;
    const deadline = Date.now() + 120_000;
    async function load() {
      try {
        const result = await requestJson(config, session, path, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setInventory(record(result));
        setError('');
        const observed = new Set(rows(result.items).map((row) => text(row.latest_detection_run_id)));
        const remaining = pending.filter((id) => !observed.has(id));
        if (remaining.length && Date.now() < deadline) timer = window.setTimeout(() => void load(), 3000);
        else if (pending.length) {
          setPending([]);
          if (remaining.length) setMessage('Some observations are still pending. Refresh to read their latest status.');
        }
      } catch (failure) {
        if (!controller.signal.aborted) setError(apiErrorMessage(failure, 'Subdomains could not be loaded.'));
      }
    }
    void load();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [config, session, path, parentId, target.kind, refresh, pending]);

  const items = rows(inventory?.items);
  const visible = useMemo(() => items.filter((item) => text(item.hostname).toLowerCase().includes(filter.toLowerCase())), [items, filter]);
  const source = record(inventory?.source);
  const sourceConfigured = source.configured === true;
  const sourceLabel = text(source.label) || SOURCE_LABELS[text(source.name)] || '';
  const unchecked = items.filter((item) => item.exposure === 'not_checked');
  const detectionEnabled = inventory?.detection_enabled === true;
  const canDetect = canStart && detectionEnabled && unchecked.some((item) => item.ownership_verified === true);

  async function confirm() {
    if (!review) return;
    const action = review;
    const controller = new AbortController();
    mutation.current = controller;
    setBusy(true); setError(''); setMessage('');
    try {
      const result = await requestJson(config, session, `${path}/${action}`, {
        method: 'POST', body: action === 'detect' ? { scope: 'unchecked' } : {}, signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      if (action === 'enumerate') {
        setMessage(enumerateSummary(record(result), text(result.source_label) || sourceLabel, text(target.value)));
      } else {
        const queued = rows(result.queued);
        setMessage(`Queued ${queued.length} fingerprint observations; ${rows(result.skipped).length} skipped; ${Number(result.deferred) || 0} left for a later batch. Each host has its own result.`);
        setPending(queued.map((row) => text(row.test_run_id)).filter(Boolean));
      }
      setReview(null); setRefresh((value) => value + 1);
    } catch (failure) {
      if (controller.signal.aborted) return;
      const payload = record((failure as { payload?: unknown } | null)?.payload);
      const code = text(payload.error);
      const label = SOURCE_LABELS[text(payload.source)] || sourceLabel;
      const known = action === 'enumerate' ? subdomainSourceErrorMessage(code, label) : '';
      setError(known || apiErrorMessage(failure, 'The subdomain action could not be completed.'));
      setReview(null);
      if (code === 'subdomain_source_not_configured') setRefresh((value) => value + 1);
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  const columns: TableColumn<DataItem>[] = [
    { key: 'hostname', label: 'Hostname', render: (row) => text(row.target_id)
      ? <a className="mono" href={buildDetailHref('target-detail', text(row.target_id))}>{text(row.hostname)}</a>
      : <span className="mono">{text(row.hostname)}</span> },
    { key: 'origin', label: 'Declaration', render: (row) => row.origin === 'discovered' ? 'Imported' : 'Declared' },
    { key: 'verification', label: 'Ownership', render: (row) => row.verification_inherited === true ? 'Verified through parent' : row.ownership_verified === true ? 'Verified' : 'Unverified' },
    ...(['waf', 'cdn', 'cloud'] as const).map((family): TableColumn<DataItem> => ({
      key: family, label: family === 'waf' ? 'WAF fingerprint' : family === 'cdn' ? 'CDN' : 'Hosting',
      render: (row) => record(row[family]).status === 'detected'
        ? providerName(text(record(row[family]).provider))
        : record(row[family]).status === 'not_detected' ? 'No match' : 'Not established',
    })),
    { key: 'exposure', label: 'Observation', render: (row) => <Badge tone="muted">{OBSERVATIONS[text(row.exposure)] ?? 'Inconclusive'}</Badge> },
    { key: 'observed_at', label: 'Observed', render: (row) => row.observed_at ? formatDate(row.observed_at) : 'Not recorded' },
  ];

  if (parentId) return <section className="td-section"><h2>Subdomains</h2><p>This host was imported under its parent domain. <a href={`${buildDetailHref('target-detail', parentId)}&tab=subdomains`}>Review the parent&apos;s subdomains</a>.</p></section>;
  if (target.kind !== 'fqdn') return <EmptyState icon={Network} title="Domain target required" body="Subdomain enumeration is available on declared domain targets." />;
  return <section className="td-section" aria-labelledby="subdomain-title">
    <header className="td-section-head"><div><h2 id="subdomain-title">Subdomains</h2><p>Review declared and imported hosts under this domain. Provider fingerprints do not establish WAF effectiveness.</p></div>
      <div className="td-actions">
        <Button variant="secondary" disabled={busy} onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={16} aria-hidden="true" />Refresh</Button>
        {canWrite ? <Button variant="secondary" disabled={!inventory || !sourceConfigured || busy} onClick={() => setReview('enumerate')}>Discover and add subdomains</Button> : null}
        {canStart ? <Button disabled={!canDetect || busy || pending.length > 0} onClick={() => setReview('detect')}>Detect unchecked hosts</Button> : null}
      </div>
    </header>
    {error ? <p role="alert" className="text-danger">{error}</p> : null}
    {message ? <p role="status">{message}</p> : null}
    {pending.length ? <p role="status">Following {pending.length} queued observations. Detection results will appear per host.</p> : null}
    {inventory && !sourceConfigured ? <p role="note">{NOT_CONFIGURED[text(source.reason)] ?? NOT_CONFIGURED_FALLBACK} Declared subdomains and existing observations are still available.</p> : null}
    {inventory && sourceConfigured && sourceLabel ? <p className="td-muted">Discovery source: {sourceLabel}. Only hostnames strictly under {text(target.value)} are imported.</p> : null}
    {record(inventory?.meta).truncated === true ? <p role="status">This is a partial inventory. Additional declared hosts can be reviewed in the Targets inventory.</p> : null}
    {inventory && record(inventory.parent).ownership_verified !== true ? <p>Verify the parent domain before testing newly imported hosts. The server checks each host&apos;s ownership and testing limits.</p> : null}
    {!canWrite ? <p>Your role can review subdomains; importing hosts requires write access.</p> : null}
    {!inventory && !error ? <EmptyState icon={Network} title="Loading subdomains" body="Reading this domain&apos;s declared hosts and recorded observations." variant="skeleton" /> : null}
    {inventory ? <>
      <label className="field"><span>Filter subdomains</span><input className="input" type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Hostname" /></label>
      <p>{visible.length} of {items.length} hosts shown. {unchecked.length} have not been checked.</p>
      {visible.length ? <DataTable<DataItem> columns={columns} items={visible} getRowId={(row) => text(row.target_id)} empty={null} />
        : <EmptyState icon={Network} title={items.length ? 'No matching subdomains' : 'No subdomains recorded'} body={items.length ? 'Change the hostname filter to see more hosts.' : 'Declare a child hostname or use the configured passive source to add subdomains. Initial provider detection is queued automatically; further checks are available in each host’s target workspace.'} />}
    </> : null}
    <ConfirmModal open={review !== null} busy={busy} onCancel={() => setReview(null)} onConfirm={() => void confirm()}
      title={review === 'enumerate' ? 'Discover and declare subdomains?' : 'Start subdomain provider detection?'}
      confirmLabel={review === 'enumerate' ? 'Discover and add' : 'Start bounded detection'}
      description={review === 'enumerate'
        ? <><p>{sourceLabel || 'The configured passive source'} will return a bounded list of hostnames strictly under {text(target.value)}. No traffic is sent to those hosts by this lookup. Newly found hostnames become declared child targets. Initial WAF/CDN detection is queued automatically and runs after ownership and safety requirements are met. Each child opens the full target workspace for further checks.</p>
          {busy ? <p role="status">Querying {sourceLabel || 'the passive source'} for hostnames under {text(target.value)}. This can take up to a minute.</p> : null}</>
        : <p>Queues a bounded batch of unchecked child targets. Each fingerprint observation uses its own ownership, signed-worker, rate and safety checks. Provider detection does not test enforcement or capacity.</p>}
    />
  </section>;
}
