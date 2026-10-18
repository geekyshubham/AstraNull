import { useEffect, useMemo, useRef, useState } from 'react';
import { Network, RefreshCw, Search } from 'lucide-react';
import { requestDiscoveryStream, requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref } from '../../lib/route-params';
import { countLabel, formatDate } from '../../lib/utils';
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
const SOURCE_LABELS: Record<string, string> = { virustotal: 'Passive DNS', virustotal_ui: 'Passive DNS', crtsh: 'Certificate Transparency logs (crt.sh)' };
const NOT_CONFIGURED: Record<string, string> = {
  disabled: 'Subdomain discovery is unavailable. You can declare child hostnames manually.',
  virustotal_api_key_missing: 'Subdomain discovery is unavailable. You can declare child hostnames manually.',
  invalid_source: 'Subdomain discovery is unavailable. You can declare child hostnames manually.',
};
const NOT_CONFIGURED_FALLBACK = 'Subdomain discovery is unavailable. You can declare child hostnames manually.';

function subdomainSourceErrorMessage(code: string, label: string): string {
  const source = label || 'The passive source';
  switch (code) {
    case 'subdomain_discovery_cancelled': return 'Discovery stopped. Hostnames already declared remain available.';
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
  const [runningAction, setRunningAction] = useState<'enumerate' | 'detect' | null>(null);
  const [progress, setProgress] = useState<DataItem>({});
  const [review, setReview] = useState<'enumerate' | 'detect' | null>(null);
  const [pending, setPending] = useState<string[]>([]);
  const mutation = useRef<AbortController | null>(null);

  useEffect(() => {
    setBusy(false); setRunningAction(null); setProgress({}); setReview(null);
    setError(''); setMessage(''); setPending([]); setInventory(null);
    return () => { mutation.current?.abort(); mutation.current = null; };
  }, [targetId]);
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
    setRunningAction(action); setProgress({ phase: 'preparing' }); setReview(null);
    let currentPhase = 'preparing';
    try {
      const result = action === 'enumerate'
        ? await requestDiscoveryStream(config, session, `${path}/${action}`, {
          signal: controller.signal, onProgress: value => {
            currentPhase = text(value.phase) || currentPhase;
            setProgress(previous => ({ ...previous, ...value }));
          },
        })
        : await requestJson(config, session, `${path}/${action}`, {
          method: 'POST', body: { scope: 'unchecked' }, signal: controller.signal,
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
      setError(action === 'enumerate' && currentPhase === 'declaring'
        ? 'Discovery could not finish. Hostnames already declared remain available. Refresh to read the latest inventory.'
        : known || apiErrorMessage(failure, 'The subdomain action could not be completed.'));
      setReview(null);
      if (currentPhase === 'declaring') setRefresh(value => value + 1);
      if (code === 'subdomain_source_not_configured') setRefresh((value) => value + 1);
    } finally {
      if (!controller.signal.aborted) { setBusy(false); setRunningAction(null); }
    }
  }

  function stopDiscovery() {
    mutation.current?.abort();
    setBusy(false); setRunningAction(null); setReview(null);
    setMessage('Discovery stopped. Hostnames already declared remain available.');
    setRefresh(value => value + 1);
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
  const sourceNote = inventory && sourceConfigured && sourceLabel ? `Source: ${sourceLabel}. Only hostnames strictly under ${text(target.value)} are imported; the lookup sends no traffic to them.` : '';
  return <section className="td-section td-subdomains" aria-labelledby="subdomain-title">
    <header className="td-section-head"><div><h2 id="subdomain-title">Subdomains</h2><p>Declared and imported hosts under <span className="mono">{text(target.value)}</span>. Provider fingerprints do not establish WAF effectiveness.</p></div>
      <div className="td-actions">
        <Button variant="ghost" size="sm" className="td-icon-button" aria-label="Refresh subdomains" title="Refresh" disabled={busy} onClick={() => { setError(''); setRefresh((value) => value + 1); }}><RefreshCw size={16} aria-hidden="true" /></Button>
        {canWrite ? <Button variant="secondary" disabled={!inventory || !sourceConfigured || busy} title={sourceNote || undefined} onClick={() => setReview('enumerate')}>Discover and add subdomains</Button> : null}
        {canStart && unchecked.length ? <Button disabled={!canDetect || busy || pending.length > 0} onClick={() => setReview('detect')}>Detect unchecked hosts</Button> : null}
      </div>
    </header>
    {error ? <p role="alert" className="form-banner error">{error}</p> : null}
    {message ? <p role="status" className="form-banner info">{message}</p> : null}
    {busy && runningAction === 'enumerate' ? <div className="td-sub-progress">
      <p role="status">{progress.phase === 'declaring'
        ? `Declaring hostnames: ${Number(progress.completed) || 0} of ${Number(progress.total) || 0}.`
        : `Discovering hostnames under ${text(target.value)}. ${Number(progress.records) > 0 ? `${Number(progress.records)} source records read.` : 'Waiting for source results.'}`}</p>
      <Button size="sm" variant="secondary" onClick={stopDiscovery}>Stop discovery</Button>
    </div> : null}
    {pending.length ? <p role="status" className="td-muted">Following {pending.length} queued observations. Detection results will appear per host.</p> : null}
    {inventory && !sourceConfigured ? <p role="note" className="td-muted">{NOT_CONFIGURED[text(source.reason)] ?? NOT_CONFIGURED_FALLBACK} Declared subdomains and existing observations are still available.</p> : null}
    {record(inventory?.meta).truncated === true ? <p role="status" className="td-muted">This is a partial inventory. Additional declared hosts can be reviewed in the Targets inventory.</p> : null}
    {inventory && record(inventory.parent).ownership_verified !== true ? <p className="td-muted">Verify the parent domain before testing newly imported hosts. The server checks each host&apos;s ownership and testing limits.</p> : null}
    {!canWrite ? <p className="td-muted">Your role can review subdomains; importing hosts requires write access.</p> : null}
    {!inventory && !error ? <EmptyState icon={Network} title="Loading subdomains" body="Reading this domain&apos;s declared hosts and recorded observations." variant="skeleton" /> : null}
    {inventory && items.length ? <>
      <div className="td-sub-toolbar">
        <label className="td-sub-filter"><Search size={15} aria-hidden="true" /><span className="sr-only">Filter subdomains</span><input type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter by hostname" /></label>
        <span className="td-muted tabular-nums">{filter ? `${visible.length} of ${items.length} hosts` : countLabel(items.length, 'host')}{unchecked.length ? ` · ${unchecked.length} not checked` : ''}</span>
      </div>
      {visible.length ? <DataTable<DataItem> columns={columns} items={visible} getRowId={(row) => text(row.target_id)} empty={null} />
        : <EmptyState icon={Network} title="No matching subdomains" body="Change the hostname filter to see more hosts." />}
      {sourceNote ? <p className="td-muted td-sub-source">{sourceNote}</p> : null}
    </> : null}
    {inventory && !items.length ? <EmptyState icon={Network} title="No subdomains recorded" body={`${sourceNote ? `${sourceNote} ` : ''}Initial provider detection is queued automatically for each host you add; further checks are available in each host’s target workspace.`} /> : null}
    <ConfirmModal open={review !== null} busy={busy} onCancel={() => setReview(null)} onConfirm={() => void confirm()}
      title={review === 'enumerate' ? 'Discover and declare subdomains?' : 'Start subdomain provider detection?'}
      confirmLabel={review === 'enumerate' ? 'Discover and add' : 'Start bounded detection'}
      description={review === 'enumerate'
        ? <p>Finds hostnames under {text(target.value)} from passive sources — no traffic is sent to them. New hosts are added as child targets and queued for WAF/CDN detection. You can stop discovery any time.</p>
        : <p>Queues WAF/CDN detection for unchecked hosts. Each host runs its own safety checks; detection does not test enforcement or capacity.</p>}
    />
  </section>;
}
