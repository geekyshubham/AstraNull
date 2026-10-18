import { useMemo, useRef, useState, type MouseEvent } from 'react';
import {
  ChevronDown,
  CircleDashed,
  Globe2,
  Info,
  Link2,
  Lock,
  Network,
  Play,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Tags,
  Target,
  Trash2
} from 'lucide-react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { EVIDENCE_STATUS_TONE, latestRunVerdict } from '../../lib/dashboard-metrics';
import { providerName } from '../../lib/domain-checks.mjs';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate, formatNumber, pluralize } from '../../lib/utils';
import { VerifyChip } from '../../lib/verify-chip';
import { AnchorButton, Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { DataTable, type TableColumn } from '../../components/ui/table';
import { EmptyState } from '../../components/ui/empty-state';
import { Select, type SelectOption } from '../../components/ui/select';
import { classifyDnsPath, declaredHost, isIpLiteral, type DnsPath } from './targets-dns-path';
import './targets-refined.css';

/** One inventory row, built by TargetsPage from the same helpers the Classic table uses. */
export type TargetRowModel = {
  item: DataItem;
  id: string;
  value: string;
  kind: string;
  kindLabel: string;
  verified: boolean;
  verificationState: string;
  verificationProvenance: string;
  tags: string[];
  source: string;
  rawSource: string;
  createdAt: unknown;
  lastRecorded: unknown;
  lastResult: ReturnType<typeof latestRunVerdict>;
};

export interface TargetsRefinedInventoryProps {
  config: PortalConfig;
  session: Session;
  loaded: boolean;
  loadError?: string | null;
  onRetry: () => void;
  totalCount: number;
  rows: TargetRowModel[];
  units: { records: number; distinctHosts: number; nonHostRecords: number };
  verifiedCount: number;
  unverifiedCount: number;
  query: string;
  onQueryChange: (value: string) => void;
  verificationFilter: string;
  onVerificationFilterChange: (value: string) => void;
  kindFilter: string;
  kindOptions: SelectOption[];
  onKindFilterChange: (value: string) => void;
  tagFilter: string;
  tagOptions: string[];
  onTagFilterChange: (value: string) => void;
  filtersActive: boolean;
  onClearFilters: () => void;
  runsUnavailable: boolean;
  canWriteTargets: boolean;
  canRunChecks: boolean;
  busy: string;
  showAdd: boolean;
  onAddTarget: (opener: HTMLElement | null) => void;
  onEditTags: (item: DataItem) => void;
  onRemove: (item: DataItem) => void;
  onRemember: (id: string, focusKey?: string) => void;
  detailHref: (id: string) => string;
}

type DnsEntry =
  | { status: 'loading' }
  | { status: 'ready'; path: DnsPath }
  | { status: 'error'; message: string };

/** Upper bound for one "Read DNS paths" action, so a large inventory never fans out unbounded reads. */
export const DNS_READ_BATCH_LIMIT = 25;
const DNS_READ_CONCURRENCY = 3;

const VERIFICATION_OPTIONS: SelectOption[] = [
  { value: 'all', label: 'All states' },
  { value: 'verified', label: 'Verified' },
  { value: 'unverified', label: 'Not verified' }
];

function shortDate(value: unknown) {
  const date = value ? new Date(typeof value === 'number' ? value : String(value)) : null;
  if (!date || Number.isNaN(date.getTime())) return formatDate(value);
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function percent(part: number, whole: number) {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

/** Declared IPs (and IP-based TCP services) need no read: there is no DNS record in front of them. */
function needsDnsRead(row: TargetRowModel) {
  const host = declaredHost(row.kind, row.value);
  return !(host && isIpLiteral(host));
}

/** Path from the list's `dns_observation`; undefined when the API predates that field and a read is needed. */
function listedDnsPath(row: TargetRowModel): DnsPath | undefined {
  if (!needsDnsRead(row)) return classifyDnsPath({ kind: row.kind, value: row.value, edgeDetection: null });
  if (!Object.prototype.hasOwnProperty.call(row.item, 'dns_observation')) return undefined;
  return classifyDnsPath({ kind: row.kind, value: row.value, edgeDetection: row.item.dns_observation ?? null });
}

function familyLabel(family: string) {
  if (family === 'cdn') return 'CDN';
  if (family === 'waf') return 'WAF';
  if (family === 'cloud') return 'cloud';
  return 'edge';
}

function KindIcon({ kind }: { kind: string }) {
  const Icon = kind === 'ip' || kind === 'tcp' ? Server : kind === 'url' || kind === 'canary' ? Link2 : kind === 'dns_zone' ? Network : Globe2;
  return <span className="rf-target-icon" aria-hidden="true"><Icon size={16} /></span>;
}

function DnsPathView({ path }: { path: DnsPath }) {
  if (path.kind === 'declared_ip') {
    return (
      <div className="rf-dns">
        <span className="rf-dns-chip" data-dns="ip"><Server size={13} aria-hidden="true" />IP</span>
        <span className="rf-dns-note">No DNS record: declared as an address</span>
      </div>
    );
  }
  if (path.kind === 'not_observed') {
    return (
      <div className="rf-dns">
        <span className="rf-dns-chip" data-dns="none"><CircleDashed size={13} aria-hidden="true" />Not observed</span>
        <span className="rf-dns-note">{path.summary}</span>
      </div>
    );
  }
  const observed = path.observedAt ? `Observed ${formatDate(path.observedAt)}` : 'Observation time not recorded';
  if (path.kind === 'cname') {
    const finalAlias = path.aliases[path.aliases.length - 1];
    return (
      <div className="rf-dns" title={`${path.host} → ${path.aliases.join(' → ')}. ${observed}.`}>
        <span className="rf-dns-chip" data-dns="cname"><Link2 size={13} aria-hidden="true" />CNAME</span>
        <span className="rf-dns-value"><span aria-hidden="true">→ </span><span className="sr-only">Alias of </span>{finalAlias}</span>
        <span className="rf-dns-note">
          {path.aliasMatch
            ? `Alias matches ${providerName(path.aliasMatch.provider)} ${familyLabel(path.aliasMatch.family)}`
            : path.aliases.length > 1 ? `${path.aliases.length} alias hops` : 'Alias provider not matched'}
        </span>
      </div>
    );
  }
  const edgeMatch = path.addressMatches.find((match) => match.family === 'cdn' || match.family === 'waf') ?? path.addressMatches[0] ?? null;
  const extra = path.addresses.length - 1;
  return (
    <div className="rf-dns" title={`${path.addresses.join(', ')}. ${observed}.`}>
      <span className="rf-dns-chip" data-dns="address"><Server size={13} aria-hidden="true" />{path.recordLabel}</span>
      <span className="rf-dns-value">{path.addresses[0]}{extra > 0 ? <span className="rf-dns-more">{` +${extra}`}</span> : null}</span>
      <span className="rf-dns-note">
        {path.kind === 'address_unchecked'
          ? `CNAME lookup completion unknown${edgeMatch ? `; in ${providerName(edgeMatch.provider)} ${familyLabel(edgeMatch.family)} range` : ''}`
          : edgeMatch ? `In ${providerName(edgeMatch.provider)} ${familyLabel(edgeMatch.family)} range` : 'No CNAME; no provider range matched'}
      </span>
    </div>
  );
}

function DnsExplainer() {
  return (
    <details className="rf-dns-explainer">
      <summary>
        <Info size={16} aria-hidden="true" />
        <span className="rf-dns-explainer-title">CNAME vs A record: what changes</span>
        <ChevronDown size={16} aria-hidden="true" className="rf-dns-explainer-chevron" />
      </summary>
      <div className="rf-dns-explainer-body">
        <p className="rf-dns-explainer-lead">
          DNS records help describe the path to a service. Neither an alias nor an address record alone proves who answers AstraNull&apos;s checks or which controls protect that path.
        </p>
        <div className="rf-dns-compare">
          <section className="rf-dns-card" aria-labelledby="rf-dns-cname-title">
            <h3 id="rf-dns-cname-title"><Link2 size={15} aria-hidden="true" />CNAME (alias)</h3>
            <dl>
              <dt>What it means</dt>
              <dd>The hostname is an alias for another name, often a CDN or WAF provider&apos;s edge hostname.</dd>
              <dt>Who answers checks</dt>
              <dd>The alias may lead to a provider&apos;s edge or a service you host. Only recorded response evidence describes how the tested path treats traffic.</dd>
              <dt>Origin exposure</dt>
              <dd>An alias does not establish origin reachability or lockdown. Validate a separately declared, verified origin relation with a reviewed bounded check.</dd>
            </dl>
          </section>
          <section className="rf-dns-card" aria-labelledby="rf-dns-a-title">
            <h3 id="rf-dns-a-title"><Server size={15} aria-hidden="true" />A / AAAA (address)</h3>
            <dl>
              <dt>What it means</dt>
              <dd>The hostname points straight at IPv4 (A) or IPv6 (AAAA) addresses.</dd>
              <dt>Who answers checks</dt>
              <dd>Whoever runs those addresses: your origin directly, or a provider&apos;s shared edge (a proxied record).</dd>
              <dt>Origin exposure</dt>
              <dd>An origin address can still have network filtering. Provider-range matches are address-index hints, not proof of protection or application identity.</dd>
            </dl>
          </section>
        </div>
        <ul className="rf-dns-explainer-notes">
          <li>Changing DNS can change the tested path, but changing the record type need not do so. Re-run edge detection after a routing change and the old TTL expire; earlier verdicts may describe the old path.</li>
          <li>A zone apex cannot hold a plain CNAME. Providers flatten it (ALIAS or ANAME), so it is observed as an A or AAAA answer.</li>
          <li>This column shows only what a recorded observation saw. AstraNull never guesses the record type from the hostname.</li>
        </ul>
      </div>
    </details>
  );
}

export function TargetsRefinedInventory(props: TargetsRefinedInventoryProps) {
  const { rows, totalCount, units, verifiedCount, unverifiedCount, canWriteTargets, canRunChecks, busy } = props;
  const [dns, setDns] = useState<Record<string, DnsEntry>>({});
  const [batchBusy, setBatchBusy] = useState(false);
  const inflight = useRef(new Set<string>());
  const failed = Boolean(props.loadError) && totalCount === 0;
  const pending = !props.loaded && totalCount === 0 && !failed;
  const statValue = (value: number) => (pending ? 'Loading' : failed ? 'Unavailable' : formatNumber(value));
  const verifiedShare = percent(verifiedCount, units.records);

  const listedPaths = useMemo(() => new Map(rows.map((row) => [row.id, listedDnsPath(row)])), [rows]);
  const pathFor = (row: TargetRowModel) => {
    const listed = listedPaths.get(row.id);
    if (listed) return listed;
    const entry = dns[row.id];
    return entry?.status === 'ready' ? entry.path : undefined;
  };
  const legacyRowCount = rows.filter((row) => !listedPaths.get(row.id)).length;

  const unreadRows = useMemo(
    () => rows.filter((row) => !listedPaths.get(row.id) && (!dns[row.id] || dns[row.id].status === 'error')),
    [rows, listedPaths, dns]
  );

  const dnsTally = useMemo(() => {
    const tally = { read: 0, cname: 0, address: 0, none: 0 };
    for (const row of rows) {
      if (!needsDnsRead(row)) continue;
      const listed = listedPaths.get(row.id);
      const entry = dns[row.id];
      const path = listed ?? (entry?.status === 'ready' ? entry.path : undefined);
      if (!path) continue;
      tally.read += 1;
      if (path.kind === 'cname') tally.cname += 1;
      else if (path.kind === 'address' || path.kind === 'address_unchecked') tally.address += 1;
      else tally.none += 1;
    }
    return tally;
  }, [rows, listedPaths, dns]);

  async function readDnsPath(row: TargetRowModel) {
    if (inflight.current.has(row.id)) return;
    inflight.current.add(row.id);
    setDns((prev) => ({ ...prev, [row.id]: { status: 'loading' } }));
    try {
      const payload = await requestJson(props.config, props.session, `/v1/targets/${encodeURIComponent(row.id)}`) as DataItem;
      const path = classifyDnsPath({ kind: row.kind, value: row.value, edgeDetection: payload?.edge_detection ?? null });
      setDns((prev) => ({ ...prev, [row.id]: { status: 'ready', path } }));
    } catch (err) {
      setDns((prev) => ({ ...prev, [row.id]: { status: 'error', message: apiErrorMessage(err, 'Could not read the recorded DNS path.') } }));
    } finally {
      inflight.current.delete(row.id);
    }
  }

  async function readShownDnsPaths() {
    const queue = unreadRows.slice(0, DNS_READ_BATCH_LIMIT);
    if (queue.length === 0) return;
    setBatchBusy(true);
    let cursor = 0;
    const worker = async () => {
      while (cursor < queue.length) {
        const row = queue[cursor];
        cursor += 1;
        await readDnsPath(row);
      }
    };
    try {
      await Promise.all(Array.from({ length: Math.min(DNS_READ_CONCURRENCY, queue.length) }, worker));
    } finally {
      setBatchBusy(false);
    }
  }

  function dnsCell(row: TargetRowModel) {
    const path = pathFor(row);
    if (path) return <DnsPathView path={path} />;
    const entry = dns[row.id];
    if (entry?.status === 'error') {
      return (
        <div className="rf-dns">
          <span className="rf-dns-error" role="alert">{entry.message}</span>
          <Button size="sm" variant="ghost" onClick={() => void readDnsPath(row)} aria-label={`Retry reading the DNS path for ${row.value}`}>
            <RefreshCw size={13} aria-hidden="true" /> Retry
          </Button>
        </div>
      );
    }
    return (
      <div className="rf-dns">
        <span className="rf-dns-note">Not read yet</span>
        <Button
          size="sm"
          variant="secondary"
          loading={entry?.status === 'loading'}
          onClick={() => void readDnsPath(row)}
          aria-label={`Read the recorded DNS path for ${row.value}`}
        >
          Read
        </Button>
      </div>
    );
  }

  const columns: TableColumn<TargetRowModel>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (row) => {
        const href = row.verified ? props.detailHref(row.id) : `${props.detailHref(row.id)}&tab=overview`;
        return (
          <div className="rf-target">
            <KindIcon kind={row.kind} />
            <div className="rf-target-copy">
              <a
                className="rf-target-name"
                href={href}
                title={row.value}
                data-focus-key={`target-name-${row.id}`}
                onClick={() => props.onRemember(row.id, `target-name-${row.id}`)}
              >
                {row.value}
              </a>
              <span className="rf-target-meta">
                <span className="rf-kind">{row.kindLabel}</span>
                <span>{`From ${row.source.replace(/_/g, ' ')}`}</span>
                {row.createdAt ? <><span aria-hidden="true">·</span><span title={formatDate(row.createdAt)}>{`Added ${shortDate(row.createdAt)}`}</span></> : null}
              </span>
              {row.tags.length > 0 ? (
                <ul className="rf-tags" aria-label={`Tags for ${row.value}`}>
                  {row.tags.map((tag) => <li key={tag} className="rf-tag">{tag}</li>)}
                </ul>
              ) : null}
            </div>
          </div>
        );
      }
    },
    {
      key: 'ownership',
      label: 'Ownership',
      render: (row) => (
        <div className="rf-ownership">
          <VerifyChip state={row.verificationState} provenance={row.verificationProvenance} />
          <span className="rf-eligibility">
            {row.verified
              ? <><ShieldCheck size={13} aria-hidden="true" />Checks can run</>
              : <><Lock size={13} aria-hidden="true" />Locked until verified</>}
          </span>
        </div>
      )
    },
    { key: 'dns', label: 'DNS path', render: dnsCell },
    {
      key: 'validated',
      label: 'Last validation',
      render: (row) => {
        if (!row.lastRecorded) {
          return <span className="rf-quiet">{props.runsUnavailable ? 'Unavailable' : 'No result yet'}</span>;
        }
        return (
          <div className="rf-validation">
            <span className="rf-validation-date" title={formatDate(row.lastRecorded)}>{shortDate(row.lastRecorded)}</span>
            {props.runsUnavailable ? (
              <Badge tone={EVIDENCE_STATUS_TONE.none} title="Validation runs did not load, so the latest verdict is unknown">Unavailable</Badge>
            ) : (
              <Badge tone={EVIDENCE_STATUS_TONE[row.lastResult?.status ?? 'none']} title={row.lastResult?.verdict ? `Latest evidence-backed verdict: ${row.lastResult.verdict}` : 'No evidence-backed verdict recorded for this target'}>
                {row.lastResult ? row.lastResult.label : 'Not recorded'}
              </Badge>
            )}
          </div>
        );
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (row) => {
        const promptVerify = !row.verified && canWriteTargets;
        const href = row.verified ? props.detailHref(row.id) : `${props.detailHref(row.id)}&tab=overview`;
        return (
          <div className="rf-row-actions">
            {row.verified && canRunChecks ? (
              <AnchorButton
                size="sm"
                variant="default"
                href={`${props.detailHref(row.id)}&tab=validate`}
                data-focus-key={`target-validate-${row.id}`}
                onClick={() => props.onRemember(row.id, `target-validate-${row.id}`)}
                aria-label={`Validate ${row.value}`}
              >
                <Play size={13} aria-hidden="true" /> Validate
              </AnchorButton>
            ) : null}
            <AnchorButton
              size="sm"
              variant={promptVerify ? 'default' : 'secondary'}
              href={href}
              data-focus-key={`target-${row.id}`}
              onClick={() => props.onRemember(row.id)}
              aria-label={promptVerify ? `Verify ownership of ${row.value}` : `Open target ${row.value}`}
            >
              {promptVerify ? 'Verify' : 'Open'}
            </AnchorButton>
            {canWriteTargets ? (
              <Button size="icon" variant="ghost" onClick={() => props.onEditTags(row.item)} aria-label={`Edit tags for ${row.value}`} title="Edit tags">
                <Tags size={15} aria-hidden="true" />
              </Button>
            ) : null}
            {canWriteTargets ? (
              <Button size="icon" variant="ghost" className="rf-remove" loading={busy === `remove-${row.id}`} onClick={() => props.onRemove(row.item)} aria-label={`Remove target ${row.value}`} title="Remove target">
                <Trash2 size={15} aria-hidden="true" />
              </Button>
            ) : null}
          </div>
        );
      }
    }
  ];

  const tagSelectOptions: SelectOption[] = [{ value: 'all', label: 'All tags' }, ...props.tagOptions.map((tag) => ({ value: tag, label: tag }))];
  const batchCount = Math.min(unreadRows.length, DNS_READ_BATCH_LIMIT);
  const batchLabel = batchCount > 0 ? `Read DNS paths (${formatNumber(batchCount)})` : 'Shown DNS paths read';

  return (
    <section className="refined rf-targets" aria-labelledby="rf-targets-title">
      <div className="rf-section-head rf-targets-head">
        <div className="rf-targets-head-copy">
          <h2 id="rf-targets-title">Target inventory</h2>
          <p>
            {formatNumber(rows.length)} of {formatNumber(totalCount)} loaded target records. Open a target for its profile and checks; Verify ownership opens its own DNS record.
          </p>
        </div>
      </div>

      <div className="rf-summary-strip rf-targets-summary" role="group" aria-label="Target inventory summary">
        <div className="rf-stat">
          <span className="rf-stat-label">Declared records</span>
          <span className="rf-stat-value">{statValue(units.records)}</span>
          <span className="rf-stat-hint">Every hostname, IP or endpoint you declared</span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Distinct hostnames</span>
          <span className="rf-stat-value">{statValue(units.distinctHosts)}</span>
          <span className="rf-stat-hint">
            {units.nonHostRecords ? `${formatNumber(units.nonHostRecords)} IP or endpoint ${pluralize(units.nonHostRecords, 'record')} not counted` : 'Normalized host identity'}
          </span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Ownership verified</span>
          <span className="rf-stat-value">{statValue(verifiedCount)}</span>
          {!pending && !failed && units.records > 0 ? (
            <span className="rf-meter" aria-hidden="true"><span className="rf-meter-fill" style={{ width: `${verifiedShare}%` }} /></span>
          ) : null}
          <span className="rf-stat-hint">
            {!pending && !failed && units.records > 0 ? `${verifiedShare}% of records; checks can run after per-check gates` : 'Can be checked after per-check gates'}
          </span>
        </div>
        <div className="rf-stat">
          <span className="rf-stat-label">Ownership pending</span>
          <span className="rf-stat-value">{statValue(unverifiedCount)}</span>
          <span className="rf-stat-hint">Locked: no external check can run</span>
        </div>
      </div>

      <div className="rf-panel rf-panel-flush rf-targets-panel">
        <div className="rf-targets-toolbar" role="group" aria-label="Target filters">
          <div className="rf-search-field">
            <label className="rf-field-label" htmlFor="rf-targets-search">Search</label>
            <div className="rf-search">
              <Search size={16} aria-hidden="true" />
              <input id="rf-targets-search" type="search" value={props.query} onChange={(event) => props.onQueryChange(event.target.value)} placeholder="Hostname, tag, provider" />
            </div>
          </div>
          <Select label="Verification" value={props.verificationFilter} options={VERIFICATION_OPTIONS} onChange={props.onVerificationFilterChange} />
          <Select label="Kind" value={props.kindFilter} options={[{ value: 'all', label: 'All kinds' }, ...props.kindOptions]} onChange={props.onKindFilterChange} />
          <Select label="Tag" value={props.tagFilter} options={tagSelectOptions} onChange={props.onTagFilterChange} />
        </div>

        <div className="rf-targets-statusbar">
          <p className="rf-result-count" aria-live="polite">
            {formatNumber(rows.length)} matching {rows.length === 1 ? 'target record' : 'target records'}
            {props.filtersActive ? <> · <button type="button" className="link-button" onClick={props.onClearFilters}>Clear filters</button></> : null}
          </p>
          <div className="rf-dns-bar">
            <p className="rf-dns-tally" aria-live="polite" title="From each target’s last recorded edge observation. No lookup or probe is sent.">
              {dnsTally.read > 0
                ? `DNS paths: ${formatNumber(dnsTally.cname)} CNAME, ${formatNumber(dnsTally.address)} A/AAAA, ${formatNumber(dnsTally.none)} not observed`
                : 'DNS paths come from each target’s last recorded edge observation. No lookup or probe is sent.'}
            </p>
            {legacyRowCount > 0 ? (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={batchBusy}
                  disabled={batchCount === 0 || batchBusy}
                  onClick={() => void readShownDnsPaths()}
                  aria-describedby="rf-dns-batch-hint"
                >
                  <RefreshCw size={13} aria-hidden="true" /> {batchLabel}
                </Button>
                <span id="rf-dns-batch-hint" className="sr-only">
                  {`Reads the recorded DNS path for up to ${DNS_READ_BATCH_LIMIT} shown targets. No DNS lookup or probe is sent.`}
                </span>
              </>
            ) : null}
          </div>
        </div>

        <DnsExplainer />

        <div className="rf-targets-table">
          <DataTable
            columns={columns}
            items={rows}
            getRowId={(row) => row.id}
            loadError={props.loadError}
            onRetry={props.onRetry}
            empty={pending ? (
              <EmptyState icon={Target} variant="skeleton" title="Loading targets" body="Reading the declared target inventory." />
            ) : (
              <EmptyState
                icon={Target}
                title={totalCount ? 'No targets match these filters' : 'No targets declared yet'}
                body={totalCount ? 'The declared inventory is unchanged; only the current filters hide it.' : 'Declare your first hostname, IP or URL. You will get a DNS TXT record to prove ownership; no probe is sent until it is verified.'}
                actionLabel={totalCount ? 'Clear filters' : undefined}
                onAction={totalCount ? props.onClearFilters : undefined}
                actions={!totalCount && canWriteTargets ? (
                  <Button type="button" onClick={(event: MouseEvent<HTMLButtonElement>) => props.onAddTarget(event.currentTarget)} aria-expanded={props.showAdd} aria-controls="target-declare-form">
                    <Plus size={15} aria-hidden="true" /> Add target
                  </Button>
                ) : undefined}
              />
            )}
          />
        </div>
        {!canWriteTargets && totalCount > 0 ? (
          <p className="rf-role-note">
            {canRunChecks
              ? 'Your role can open and validate targets but cannot change tags or remove targets.'
              : 'Your role can open targets but cannot change tags or remove targets.'}
          </p>
        ) : null}
      </div>
    </section>
  );
}
