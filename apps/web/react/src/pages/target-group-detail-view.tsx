import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Activity, Bot, ShieldHalf, Target, TriangleAlert } from 'lucide-react';
import { requestJson } from '../lib/api';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { VerifyChip, resolveVerifyChipState } from '../lib/verify-chip';
import { emptyStateFromApi, PortalLoadingSkeleton } from '../lib/empty-from-api';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Badge } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs, type TabOption } from '../components/ui/tabs';

type OnboardTab = 'fqdn' | 'ip' | 'cloud';

const ONBOARD_TAB_OPTIONS: TabOption<OnboardTab>[] = [
  { id: 'fqdn', label: 'Domain · DNS TXT' },
  { id: 'ip', label: 'IP address · Agent callback' },
  { id: 'cloud', label: 'Cloud provider · pull inventory' }
];

const DETAIL_MODAL_STYLES_ID = 'detail-modal-primitive-styles';
const detailModalStyles = `
.detail-modal.modal-confirm {
  padding: 0;
  max-width: min(560px, calc(100% - 32px));
  width: min(560px, calc(100% - 32px));
  max-height: min(88vh, 920px);
  display: flex;
  flex-direction: column;
}
.detail-modal.detail-modal-wide.modal-confirm {
  max-width: min(920px, calc(100% - 32px));
  width: min(920px, calc(100% - 32px));
}
.detail-modal .detail-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-soft);
}
.detail-modal .detail-modal-head h3 {
  margin: 0;
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 600;
  color: var(--fg);
}
.detail-modal .detail-modal-body {
  padding: 18px 20px;
  overflow-y: auto;
}
.detail-modal .detail-modal-body .tabs {
  margin-bottom: var(--space-4);
}
`;

function ensureDetailModalStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(DETAIL_MODAL_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = DETAIL_MODAL_STYLES_ID;
  node.textContent = detailModalStyles;
  document.head.appendChild(node);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function targetVerificationState(target: DataItem) {
  return getString(target, ['verification_state', 'verification', 'state'], 'unverified');
}

function targetEligibility(target: DataItem) {
  return getString(target, ['eligibility'], targetVerificationState(target) === 'unverified' ? 'not_eligible' : 'eligible');
}

function DetailStatusBanners({ loadError, message, error }: { loadError: string; message: string; error: string }) {
  return (
    <>
      {loadError ? <div className="form-banner error" role="alert">{loadError}</div> : null}
      {(message || error) && !loadError ? (
        <div className={error ? 'form-banner error' : 'form-banner'} role={error ? 'alert' : 'status'}>
          {error || message}
        </div>
      ) : null}
    </>
  );
}

function DetailModal({
  title,
  onClose,
  children,
  wide = true
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  ensureDetailModalStyles();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => {
      if (dialog?.open) dialog.close();
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      className={`modal-confirm detail-modal${wide ? ' detail-modal-wide' : ''}`}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="detail-modal-head">
        <h3 id={titleId}>{title}</h3>
        <Button size="sm" variant="ghost" onClick={onClose} aria-label="Close dialog">
          Close
        </Button>
      </div>
      <div className="detail-modal-body">{children}</div>
    </dialog>
  );
}

export function TargetGroupDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [dnsChallenge, setDnsChallenge] = useState<DataItem | null>(null);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<DataItem | null>(null);
  const [ladder, setLadder] = useState<DataItem | null>(null);
  const [ladderLoading, setLadderLoading] = useState(true);
  const [connectors, setConnectors] = useState<DataItem[]>([]);
  const [connectorsMeta, setConnectorsMeta] = useState<DataItem | null>(null);
  const [inventoryProvider, setInventoryProvider] = useState<string | null>(null);
  const [inventoryRows, setInventoryRows] = useState<DataItem[]>([]);
  const [inventoryMeta, setInventoryMeta] = useState<DataItem | null>(null);
  const [selectedInventory, setSelectedInventory] = useState<Set<string>>(new Set());
  const [showLoaModal, setShowLoaModal] = useState(false);
  const [showOnboardModal, setShowOnboardModal] = useState(false);
  const [onboardTab, setOnboardTab] = useState<OnboardTab>('fqdn');

  const targets = Array.isArray(entity.targets) ? entity.targets as DataItem[] : [];
  const agents = Array.isArray(data.agents) ? data.agents as DataItem[] : [];
  const relatedRuns = Array.isArray(entity.runs_recent) ? entity.runs_recent as DataItem[] : [];
  const relatedFindings = Array.isArray(entity.findings_on_group) ? entity.findings_on_group as DataItem[] : [];
  const groupMeta = entity.meta && typeof entity.meta === 'object' && !Array.isArray(entity.meta) ? entity.meta as DataItem : null;
  const targetCount = String(entity.target_count ?? targets.length);
  const loaState = getString(entity, ['loa_state', 'loa_status'], getString(entity.loa as DataItem | undefined, ['state'], 'required'));
  const loaSigned = loaState.toLowerCase() === 'signed';
  const ladderSteps = Array.isArray(ladder?.steps) ? ladder.steps as DataItem[] : [];

  useEffect(() => {
    let cancelled = false;
    setLadderLoading(true);
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/verification-ladder`)
      .then((payload) => { if (!cancelled) setLadder(payload as DataItem); })
      .catch(() => { if (!cancelled) setLadder(null); })
      .finally(() => { if (!cancelled) setLadderLoading(false); });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

  useEffect(() => {
    let cancelled = false;
    requestJson(config, session, '/v1/connectors')
      .then((payload) => {
        if (cancelled) return;
        const envelope = payload as DataItem;
        setConnectors(Array.isArray(envelope.items) ? envelope.items as DataItem[] : []);
        setConnectorsMeta(envelope.meta && typeof envelope.meta === 'object' ? envelope.meta as DataItem : null);
      })
      .catch((err) => {
        if (!cancelled) {
          setConnectors([]);
          const payload = (err as Error & { payload?: DataItem })?.payload;
          const payloadMeta = payload?.meta && typeof payload.meta === 'object' ? payload.meta as DataItem : null;
          setConnectorsMeta(payloadMeta ?? (payload ? { empty_reason: getString(payload, ['error', 'message']) } : null));
        }
      });
    return () => { cancelled = true; };
  }, [config, session]);

  async function runAction(label: string, action: () => Promise<void>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  function openOnboardModal(tab: OnboardTab = 'fqdn') {
    setOnboardTab(tab);
    setError('');
    setMessage('');
    setShowOnboardModal(true);
  }

  async function addTarget(kind: string, value: string, expectedBehavior: string) {
    const trimmed = value.trim();
    if (!trimmed) {
      setError('A target value is required.');
      setMessage('');
      return;
    }
    setBusy(`add-target-${kind}`);
    setError('');
    setMessage('');
    try {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/targets`, {
        method: 'POST',
        body: { kind, value: trimmed, expected_behavior: expectedBehavior || null }
      });
      setMessage('Target declared.');
      setShowOnboardModal(false);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to declare target.');
    } finally {
      setBusy('');
    }
  }

  function submitFqdnTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    void addTarget('fqdn', String(form.get('value') ?? ''), String(form.get('expected_behavior') ?? ''));
  }

  function submitIpTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const ip = String(form.get('value') ?? '').trim();
    const port = String(form.get('port') ?? '').trim();
    void addTarget('ip', port ? `${ip}:${port}` : ip, String(form.get('expected_behavior') ?? ''));
  }

  async function issueDnsChallenge() {
    await runAction(`dns-issue-${entityId}`, async () => {
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/issue`, { method: 'POST' }) as DataItem;
      const challenge = result.challenge && typeof result.challenge === 'object' ? result.challenge as DataItem : result;
      setDnsChallenge(challenge);
      setDnsVerifyResult(null);
    }, 'DNS TXT challenge issued.');
  }

  async function verifyDnsChallenge() {
    await runAction(`dns-verify-${entityId}`, async () => {
      const challengeId = getString(dnsChallenge, ['id', 'challenge_id'], '');
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/verify`, {
        method: 'POST',
        body: challengeId ? { challenge_id: challengeId } : {}
      }) as DataItem;
      setDnsVerifyResult(result);
    }, 'DNS ownership verification completed.');
  }

  async function openInventory(connectorId: string) {
    setInventoryProvider(connectorId);
    setBusy(`inventory-${connectorId}`);
    try {
      const payload = await requestJson(config, session, `/v1/connectors/${encodeURIComponent(connectorId)}/inventory`) as DataItem;
      setInventoryRows(Array.isArray(payload.items) ? payload.items as DataItem[] : []);
      setInventoryMeta(payload.meta && typeof payload.meta === 'object' ? payload.meta as DataItem : null);
      setSelectedInventory(new Set());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Inventory request failed.');
      setInventoryRows([]);
      setInventoryMeta({ empty_reason: err instanceof Error ? err.message : 'Inventory request failed.' });
    } finally {
      setBusy('');
    }
  }

  async function importInventory() {
    if (!inventoryProvider || selectedInventory.size === 0) return;
    await runAction(`import-${inventoryProvider}`, async () => {
      for (const rowId of selectedInventory) {
        const row = inventoryRows.find((item) => getString(item, ['id', 'value'], '') === rowId);
        if (!row) continue;
        await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/targets`, {
          method: 'POST',
          body: {
            kind: getString(row, ['kind'], 'fqdn'),
            value: getString(row, ['value', 'name'], rowId),
            source: inventoryProvider
          }
        });
      }
      setInventoryProvider(null);
      setInventoryRows([]);
      setSelectedInventory(new Set());
    }, 'Selected inventory rows imported.');
  }

  async function runBoundedTest(targetId: string, targetGroupId: string) {
    await runAction(`run-test-${targetId}`, async () => {
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: targetId }
      });
    }, 'Bounded test run started.');
  }

  async function submitLoa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get('attested') !== 'on') {
      setError('Attestation is required before signing LOA.');
      return;
    }
    await runAction(`loa-${entityId}`, async () => {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/loa`, {
        method: 'POST',
        body: {
          attested: true,
          signer_name: String(form.get('signer_name') ?? '').trim(),
          signer_title: String(form.get('signer_title') ?? '').trim(),
          signed_date: String(form.get('signed_date') ?? '').trim()
        }
      });
      setShowLoaModal(false);
    }, 'LOA signed and recorded in custody ledger.');
  }

  const targetColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', id)}>
            {getString(item, ['value'], id)}
          </AnchorButton>
        );
      }
    },
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
    { key: 'value', label: 'Value', render: (item) => <span className="mono">{getString(item, ['value'], '—')}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => {
        const state = targetVerificationState(item);
        const chip = resolveVerifyChipState(state, getString(item, ['verification_title', 'verification_provenance'], `Verification ${state} from target API.`));
        return <span className={chip.className} title={chip.title}><span className="vc-dot" aria-hidden="true" />{chip.label}</span>;
      }
    },
    {
      key: 'eligibility',
      label: 'Eligibility',
      render: (item) => <Badge tone={targetEligibility(item).startsWith('not') ? 'warn' : 'success'} title={`Eligibility ${targetEligibility(item)} from target API`}>{targetEligibility(item)}</Badge>
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const eligible = !targetEligibility(item).startsWith('not');
        return (
          <div className="row-end-actions">
            <Button size="sm" variant="ghost" onClick={() => { window.location.hash = buildDetailHref('target-detail', id).replace(/^#/, ''); }}>Verify</Button>
            <Button
              size="sm"
              variant="ghost"
              className={eligible ? undefined : 'is-locked'}
              disabled={!eligible || busy === `run-test-${id}`}
              title={eligible ? 'Run bounded test' : 'Verify to enable testing'}
              onClick={() => { void runBoundedTest(id, entityId); }}
            >
              Run test
            </Button>
          </div>
        );
      }
    }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const targetId = getString(item, ['target_id'], '');
        return targetId
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', targetId)}>{targetId}</AnchorButton>
          : <span className="muted">group-level</span>;
      }
    },
    {
      key: 'finding',
      label: 'Finding',
      render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', getString(item, ['id'], ''))}>{getString(item, ['title', 'id'], '')}</AnchorButton>
    },
    { key: 'severity', label: 'Severity', render: (item) => getString(item, ['severity'], 'unknown') },
    { key: 'status', label: 'Status', render: (item) => getString(item, ['status'], 'open') }
  ];

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', getString(item, ['id'], ''))}>{getString(item, ['id'], '')}</AnchorButton> },
    { key: 'policy', label: 'Policy', render: (item) => getString(item, ['policy_id', 'test_policy_id'], '—') },
    { key: 'checks', label: 'Checks', render: (item) => String(item.check_count ?? getString(item, ['check_id'], '—')) },
    { key: 'verdict', label: 'Verdict', render: (item) => getString(item, ['verdict', 'status'], 'pending') },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
    { key: 'agent', label: 'Agent', render: (item) => getString(item, ['agent_id'], '—') }
  ];

  return (
    <div className="content stack-tight">
      <div className="page-head">
        <div>
          <p className="eyebrow">Declared business service</p>
          <h1 className="page-title">{getString(entity, ['name'], entityId)}</h1>
          <p className="muted mono">{entityId}</p>
        </div>
        <AnchorButton size="sm" variant="secondary" href="#target-groups">All groups</AnchorButton>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      <DetailStatusBanners loadError={loadError} message={message} error={error} />

      {ladderLoading ? <PortalLoadingSkeleton rows={1} /> : null}
      {!ladderLoading && ladderSteps.length === 0 ? (
        emptyStateFromApi({
          loading: ladderLoading,
          icon: Target,
          meta: ladder?.meta && typeof ladder.meta === 'object' ? ladder.meta as DataItem : null,
        })
      ) : null}
      {!ladderLoading && ladderSteps.length > 0 ? (
      <ol className="verify-ladder" aria-label="Ownership verification ladder">
        {ladderSteps.map((step, index) => {
          const done = step.done === true;
          const now = !done && ladderSteps.slice(0, index).every((entry) => entry.done === true);
          return (
            <li key={getString(step, ['id'], String(index))} className={`vl-step${done ? ' is-done' : ''}${now ? ' is-now' : ''}`}>
              <span className="vl-num">{index + 1}</span>
              <div className="vl-body">
                <strong>{getString(step, ['label'], 'Step')}</strong>
                <span className="vl-meta">{getString(step, ['count'], '0')}/{getString(step, ['total'], '0')}</span>
              </div>
            </li>
          );
        })}
      </ol>
      ) : null}

      <div className="metric-grid four">
        <div className="kpi"><div className="kpi-label">Group id</div><div className="kpi-value mono">{entityId}</div></div>
        <div className="kpi"><div className="kpi-label">Environment</div><div className="kpi-value">{getString(entity, ['environment_id'], '—')}</div></div>
        <div className="kpi"><div className="kpi-label">Criticality</div><div className="kpi-value">{getString(entity, ['criticality', 'business_criticality'], '—')}</div></div>
        <div className="kpi"><div className="kpi-label">Total targets</div><div className="kpi-value">{targetCount}</div></div>
        <div className="kpi"><div className="kpi-label">LOA</div><div className="kpi-value"><Badge tone={loaSigned ? 'success' : 'warn'} title={`LOA state ${loaState} from target group API`}>{loaSigned ? 'Signed' : 'Required'}</Badge></div></div>
      </div>

      <div className="callout callout-loa" data-loa-state={loaSigned ? 'signed' : 'required'}>
        <span className="callout-icon" aria-hidden="true"><ShieldHalf size={16} /></span>
        <div>
          <p className="callout-title">{loaSigned ? 'LOA signed' : 'LOA signature required'}</p>
          <p className="callout-desc">
            {loaSigned
              ? `${getString(entity.loa as DataItem | undefined, ['signer_name'], getString(entity, ['loa_signer'], '—'))} · ${getString(entity.loa as DataItem | undefined, ['custody_digest_sha256', 'digest'], getString(entity, ['loa_digest'], '—'))} · ${formatDate((entity.loa as DataItem | undefined)?.signed_at ?? entity.loa_signed_at)}`
              : 'Sign the authorization artifact before SOC-gated checks can execute on this group.'}
          </p>
        </div>
        <div className="callout-actions">
          {!loaSigned ? (
            <>
              <Button size="sm" onClick={() => setShowLoaModal(true)}>Open target group and sign LOA</Button>
              <Button size="sm" variant="ghost" onClick={() => void verifyDnsChallenge()} loading={busy === `dns-verify-${entityId}`}>Review DNS status</Button>
            </>
          ) : null}
        </div>
      </div>

      <Card>
        <CardHeader>
          <div>
            <CardTitle>Declared targets</CardTitle>
            <CardDescription>Env <span className="mono">{getString(entity, ['environment_id'], '—')}</span> · expected behavior declared per row</CardDescription>
          </div>
          <Button size="sm" onClick={() => openOnboardModal()}>Edit targets</Button>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={targetColumns}
            items={targets}
            className="tg-targets-table"
            empty={
              <EmptyState
                icon={Target}
                title="No targets declared yet"
                body="Declare a domain, IP, or cloud inventory selection to start validating this group. Nothing runs until a target is verified."
                actionLabel="+ Add Target"
                onAction={() => openOnboardModal()}
              />
            }
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Findings on this group</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={findingColumns} items={relatedFindings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: groupMeta ? { empty_reason: getString(groupMeta, ['findings_empty_reason'], '') } : null })} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Recent runs</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={runColumns} items={relatedRuns} empty={emptyStateFromApi({ icon: Activity, meta: groupMeta ? { empty_reason: getString(groupMeta, ['runs_empty_reason'], '') } : null, actionHref: '#runs', actionLabel: 'Open test runs' })} />
        </CardContent>
      </Card>

      {inventoryProvider ? (
        <DetailModal title={`Provider inventory · ${inventoryProvider}`} onClose={() => setInventoryProvider(null)}>
            <div className="inv-body">
              <DataTable
                columns={[
                  { key: 'select', label: 'Select', render: (item) => {
                    const id = getString(item, ['id', 'value'], '');
                    const label = getString(item, ['value', 'name'], id);
                    return (
                      <input
                        type="checkbox"
                        checked={selectedInventory.has(id)}
                        aria-label={`Select ${label}`}
                        onChange={(event) => {
                      setSelectedInventory((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(id);
                        else next.delete(id);
                        return next;
                      });
                    }}
                      />
                    );
                  } },
                  { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
                  { key: 'value', label: 'Value', render: (item) => getString(item, ['value', 'name'], '—') }
                ]}
                items={inventoryRows}
                empty={emptyStateFromApi({ icon: Bot, meta: inventoryMeta })}
              />
              <div className="row-actions">
                <Button size="sm" disabled={selectedInventory.size === 0 || busy !== ''} loading={busy.startsWith('import-')} onClick={() => void importInventory()}>Import selected</Button>
              </div>
            </div>
        </DetailModal>
      ) : null}

      {showOnboardModal ? (
        <DetailModal title="Onboard a target" onClose={() => setShowOnboardModal(false)}>
          <Tabs
            value={onboardTab}
            options={ONBOARD_TAB_OPTIONS}
            onChange={(value) => setOnboardTab(value)}
            ariaLabel="Target onboarding method"
          />
          {onboardTab === 'fqdn' ? (
            <div className="stack-tight">
              <p className="muted">Prove you control the domain by publishing a one-time TXT record. Verification is required before any probe runs.</p>
              <form className="product-form" onSubmit={submitFqdnTarget}>
                <label className="full"><span>Domain</span><input name="value" className="mono" placeholder="origin.example.com" required /></label>
                <label>
                  <span>Expected behavior</span>
                  <select name="expected_behavior" defaultValue="block_at_edge">
                    <option value="block_at_edge">block_at_edge</option>
                    <option value="absorb_at_origin">absorb_at_origin</option>
                    <option value="rate_shape">rate_shape</option>
                  </select>
                </label>
                <label>
                  <span>Bind to agent (optional)</span>
                  <select name="agent_id" defaultValue="">
                    <option value="">any agent in {getString(entity, ['environment_id'], 'this environment')}</option>
                    {agents.map((agent) => {
                      const optId = getString(agent, ['id'], '');
                      return <option key={optId} value={optId}>{optId} · {getString(agent, ['hostname', 'name'], optId)}</option>;
                    })}
                  </select>
                </label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-target-fqdn'}>Add target</Button>
                  <Button type="button" variant="secondary" loading={busy === `dns-issue-${entityId}`} onClick={() => void issueDnsChallenge()}>Issue DNS challenge</Button>
                </div>
              </form>
              <div className="dns-challenge">
                <div className="dns-head">
                  <span className="eyebrow">Challenge state</span>
                  <VerifyChip
                    state={getString(dnsVerifyResult?.challenge as DataItem | undefined, ['state'], getString(dnsChallenge, ['state'], dnsVerifyResult?.verified === true ? 'dns_verified' : 'pending'))}
                    provenance={getString(dnsVerifyResult, ['meta', 'provenance'], 'DNS ownership verification API')}
                  />
                </div>
                <div className="dns-fields">
                  <div className="dns-field"><span className="dns-key">Name</span><span className="dns-val mono">{getString(dnsChallenge, ['record_name', 'name'], '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">Value</span><span className="dns-val mono">{getString(dnsChallenge, ['record_value', 'value'], '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">TTL</span><span className="dns-val mono">{getString(dnsChallenge, ['ttl', 'ttl_seconds'], '—')}</span></div>
                </div>
                <div className="dns-footer row-actions">
                  <Button size="sm" variant="ghost" loading={busy === `dns-verify-${entityId}`} onClick={() => void verifyDnsChallenge()}>Check now</Button>
                  {dnsVerifyResult?.verified === false ? <span className="muted small">Last checked {formatDate(dnsVerifyResult.checked_at ?? dnsVerifyResult.updated_at)}</span> : null}
                </div>
              </div>
            </div>
          ) : null}
          {onboardTab === 'ip' ? (
            <div className="stack-tight">
              <p className="muted">You cannot prove control of an IP with DNS. Install an agent inside that instance. When the agent registers, its outbound call reveals the public IP and binds the target to a verified agent.</p>
              <form className="product-form" onSubmit={submitIpTarget}>
                <label><span>IP address</span><input name="value" className="mono" placeholder="203.0.113.10" required /></label>
                <label><span>Protocol / port</span><input name="port" className="mono" placeholder="443" /></label>
                <label>
                  <span>Expected behavior</span>
                  <select name="expected_behavior" defaultValue="absorb_at_origin">
                    <option value="absorb_at_origin">absorb_at_origin</option>
                    <option value="block_at_edge">block_at_edge</option>
                    <option value="rate_shape">rate_shape</option>
                  </select>
                </label>
                <label className="full"><span>Notes (optional)</span><input name="notes" placeholder="Origin behind CDN · single-AZ · IPv4 only" /></label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-target-ip'}>Register &amp; wait for agent</Button>
                  <AnchorButton size="sm" variant="secondary" href="#agents">Open agent install</AnchorButton>
                </div>
              </form>
              <div className="dns-challenge">
                <div className="dns-head">
                  <span className="eyebrow">Agent callback</span>
                  <VerifyChip state="pending" provenance="Awaiting agent heartbeat from this IP" />
                </div>
                <ol className="muted small">
                  <li>Install an agent on any host that can reach the target IP (container image, Helm chart, or native package from the Agents screen).</li>
                  <li>Bind it at deploy time with <span className="mono">ASTRANULL_TARGET_GROUP={entityId}</span>. No inbound port needed.</li>
                  <li>When the agent heartbeats, AstraNull records its <span className="mono">discovered_public_ip</span> and matches it against the IP you registered.</li>
                  <li>Verified after a probe + agent correlation on the same nonce.</li>
                </ol>
              </div>
            </div>
          ) : null}
          {onboardTab === 'cloud' ? (
            <div className="stack-tight">
              <p className="muted">Connect a provider once, then pick which zones or instances belong in this target group. AstraNull normalizes the inventory and files a DNS or agent challenge for each selection.</p>
              {connectors.length === 0 ? emptyStateFromApi({ icon: Bot, meta: connectorsMeta }) : null}
              <div className="provider-grid">
                {connectors.map((connector) => {
                  const connectorId = getString(connector, ['id'], '');
                  const providerLabel = getString(connector, ['name', 'provider'], connectorId);
                  const scope = getString(connector, ['scope', 'config_json.scope'], getString(connector.config_json as DataItem | undefined, ['scope'], '—'));
                  return (
                    <div className="provider-card" key={connectorId}>
                      <div className="pc-head">
                        <span className="pc-mark">{providerLabel.slice(0, 2).toUpperCase()}</span>
                        <h3>{providerLabel}</h3>
                      </div>
                      <p>Scope required: <span className="mono">{scope}</span></p>
                      <p className="muted small">Status: {getString(connector, ['status', 'state'], 'unknown')}</p>
                      <div className="pc-actions">
                        <Button size="sm" variant="ghost" loading={busy === `inventory-${connectorId}`} onClick={() => void openInventory(connectorId)}>Open inventory</Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}
        </DetailModal>
      ) : null}

      {showLoaModal ? (
        <DetailModal title={`Sign LOA · ${getString(entity, ['name'], entityId)}`} onClose={() => setShowLoaModal(false)}>
            <form className="loa-body product-form" onSubmit={(event) => void submitLoa(event)}>
              <div className="loa-doc">
                <h4>Authorization artifact</h4>
                <dl className="loa-meta">
                  <dt>Customer</dt><dd>{getString(data.tenant, ['name', 'display_name'], session.tenant_id ?? '—')}</dd>
                  <dt>Tenant</dt><dd className="mono">{session.tenant_id ?? getString(data.state, ['tenant_id'], '—')}</dd>
                  <dt>Target group</dt><dd>{getString(entity, ['name'], entityId)}</dd>
                </dl>
              </div>
              <label className="checkrow full"><input type="checkbox" name="attested" /><span>I attest that declared targets in scope are authorized for bounded validation.</span></label>
              <label><span>Signer name</span><input name="signer_name" required /></label>
              <label><span>Signer title</span><input name="signer_title" required /></label>
              <label><span>Signed date</span><input name="signed_date" type="date" required /></label>
              <div className="form-actions"><Button type="submit" loading={busy === `loa-${entityId}`}>Sign LOA</Button></div>
            </form>
        </DetailModal>
      ) : null}
    </div>
  );
}