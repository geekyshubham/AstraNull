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
  const sourceConfigured = record(inventory?.source).configured === true;
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
        setMessage(`Added ${rows(result.created).length} subdomains; ${Number(result.already_declared) || 0} already declared; ${rows(result.failed).length} could not be added.${result.truncated ? ' The source returned a partial list; you can import again later.' : ''} Review the hosts before starting detection.`);
      } else {
        const queued = rows(result.queued);
        setMessage(`Queued ${queued.length} fingerprint observations; ${rows(result.skipped).length} skipped; ${Number(result.deferred) || 0} left for a later batch. Each host has its own result.`);
        setPending(queued.map((row) => text(row.test_run_id)).filter(Boolean));
      }
      setReview(null); setRefresh((value) => value + 1);
    } catch (failure) {
      if (!controller.signal.aborted) setError(apiErrorMessage(failure, 'The subdomain action could not be completed.'));
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
    {inventory && !sourceConfigured ? <p>Passive discovery is not configured for this deployment. Declared subdomains and existing observations are still available.</p> : null}
    {record(inventory?.meta).truncated === true ? <p role="status">This is a partial inventory. Additional declared hosts can be reviewed in the Targets inventory.</p> : null}
    {inventory && record(inventory.parent).ownership_verified !== true ? <p>Verify the parent domain before testing newly imported hosts. The server checks each host&apos;s ownership and testing limits.</p> : null}
    {!canWrite ? <p>Your role can review subdomains; importing hosts requires write access.</p> : null}
    {!inventory && !error ? <EmptyState icon={Network} title="Loading subdomains" body="Reading this domain&apos;s declared hosts and recorded observations." variant="skeleton" /> : null}
    {inventory ? <>
      <label className="field"><span>Filter subdomains</span><input className="input" type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Hostname" /></label>
      <p>{visible.length} of {items.length} hosts shown. {unchecked.length} have not been checked.</p>
      {visible.length ? <DataTable<DataItem> columns={columns} items={visible} getRowId={(row) => text(row.target_id)} empty={null} />
        : <EmptyState icon={Network} title={items.length ? 'No matching subdomains' : 'No subdomains recorded'} body={items.length ? 'Change the hostname filter to see more hosts.' : 'Declare a child hostname or use the configured passive source to add subdomains. Detection starts only after you review the hosts.'} />}
    </> : null}
    <ConfirmModal open={review !== null} busy={busy} onCancel={() => setReview(null)} onConfirm={() => void confirm()}
      title={review === 'enumerate' ? 'Discover and declare subdomains?' : 'Start subdomain provider detection?'}
      confirmLabel={review === 'enumerate' ? 'Discover and add' : 'Start bounded detection'}
      description={review === 'enumerate'
        ? <p>The configured passive source will return a bounded list strictly under {text(target.value)}. Newly found hostnames become declared child targets. No external detection starts until you review the imported list and choose it separately.</p>
        : <p>Queues a bounded batch of unchecked child targets. Each fingerprint observation uses its own ownership, signed-worker, rate and safety checks. Provider detection does not test enforcement or capacity.</p>}
    />
  </section>;
}
