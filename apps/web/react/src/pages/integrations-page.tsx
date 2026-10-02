import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { BellRing, BookOpen, ExternalLink, FileCheck2, KeyRound, PlugZap, ShieldCheck, Target, type LucideIcon } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { FormModal, formatMutationSuccessMessage, useConfirmModal } from '../lib/crud-ui';
import { apiErrorMessage } from '../lib/error-messages';
import { DataTable, type TableColumn } from '../components/ui/table';
import { AnchorButton, Button } from '../components/ui/button';
import { RoleRestrictedCard } from '../components/ui/role-restricted';
import { requestJson } from '../lib/api';
import { canReadDataset, sessionHasPermission } from '../lib/dataset-access.mjs';
import { NAV_GROUP_LABELS, ROUTE_BY_ID } from '../lib/navigation';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { formatDate, formatNumber } from '../lib/utils';
import { ProviderLogo, type ProviderLogoId } from '../components/integrations/provider-logos';
import { getProviderSetupGuide } from '../components/integrations/provider-setup-guides';
import { NotificationChannelsPanel } from '../components/integrations/notification-channels';
import { INTEGRATION_TILE_STYLES } from '../components/integrations/integration-tile-styles';
import { prefersReducedMotion } from '../lib/motion';
import { INTEGRATIONS_PAGE_STYLES } from './integrations-page-styles';

// --- Local page shell (self-contained so concurrent edits to page-components.tsx
//     never break this page; mirrors the shared presentational primitives). ---
function PageHeader({ route, eyebrow, actions }: { route: RouteId; eyebrow?: string; actions?: ReactNode }) {
  const item = ROUTE_BY_ID.get(route);
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow ?? (item ? NAV_GROUP_LABELS[item.group] : undefined)}</p>
        <h1>{item?.label}</h1>
        <p>{item?.description}</p>
      </div>
      {actions ? <div className="row-actions">{actions}</div> : null}
    </div>
  );
}

function PageContextSummary({ children }: { children: ReactNode }) {
  return <p className="page-context-summary">{children}</p>;
}

function PanelCardHeader({ title, description, trailing }: { title: ReactNode; description?: ReactNode; trailing?: ReactNode }) {
  const headings = (
    <>
      <CardTitle>{title}</CardTitle>
      {description ? <CardDescription>{description}</CardDescription> : null}
    </>
  );
  if (!trailing) return <CardHeader>{headings}</CardHeader>;
  return (
    <CardHeader>
      <div>{headings}</div>
      {trailing}
    </CardHeader>
  );
}

function CalloutNote({ icon: Icon, tone, children }: { icon: LucideIcon; tone?: 'info' | 'warn'; children: ReactNode }) {
  return (
    <div className={tone ? `callout ${tone}` : 'callout'}>
      <Icon size={18} aria-hidden />
      <span>{children}</span>
    </div>
  );
}

// --- Local data readers (mirrors the private helpers in page-components.tsx). ---
function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = (item as Record<string, unknown>)[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let cursor: unknown = item;
  for (const key of path) {
    if (!cursor || typeof cursor !== 'object') return null;
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor && typeof cursor === 'object' ? (cursor as DataItem) : null;
}

function getOptionalNumber(item: DataItem | null | undefined, keys: string[]) {
  if (!item) return null;
  for (const key of keys) {
    const value = (item as Record<string, unknown>)[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  }
  return null;
}

const CONNECTOR_SNAPSHOT_KIND_OPTIONS = [
  { value: 'waf_policy', label: 'WAF policy' },
  { value: 'cdn_property', label: 'CDN property' },
  { value: 'dns_zone', label: 'DNS zone' },
  { value: 'cloud_asset', label: 'Cloud asset' },
  { value: 'vulnerability', label: 'Vulnerability' },
] as const;

type ProviderBackend = 'cloudflare' | 'akamai_edgedns' | 'namecheap' | 'godaddy' | 'ibm_ns1' | 'aws_waf' | 'generic_waf';

type ProviderDirectoryEntry = {
  id: string;
  label: string;
  logo: ProviderLogoId;
  backendProvider: ProviderBackend;
  supportsCredentialPolling: boolean;
  capability: string;
  description: string;
  credentialExample?: string;
};

const PROVIDER_DIRECTORY: readonly ProviderDirectoryEntry[] = [
  {
    id: 'cloudflare',
    label: 'Cloudflare',
    logo: 'cloudflare',
    backendProvider: 'cloudflare',
    supportsCredentialPolling: true,
    capability: 'Read-only zone and ruleset polling',
    description: 'Poll bounded zone inventory and zone rulesets with a scoped read-only token. Imported domains retain exact provider evidence.',
    credentialExample: 'Provider token or {"api_token":"..."}',
  },
  {
    id: 'akamai_edgedns',
    label: 'Akamai EdgeDNS',
    logo: 'akamai',
    backendProvider: 'akamai_edgedns',
    supportsCredentialPolling: true,
    capability: 'Read-only zone polling',
    description: 'EdgeGrid-authenticated bounded polling for Edge DNS zones and record sets. Only read-only access is requested.',
    credentialExample: '{"host":"...luna.akamaiapis.net","access_token":"...","client_token":"...","client_secret":"..."}',
  },
  {
    id: 'godaddy',
    label: 'GoDaddy',
    logo: 'godaddy',
    backendProvider: 'godaddy',
    supportsCredentialPolling: true,
    capability: 'Read-only domain polling',
    description: 'List account domains with a Production key and secret. Only the domain list endpoint is called.',
    credentialExample: '{"key":"...","secret":"..."}',
  },
  {
    id: 'namecheap',
    label: 'Namecheap',
    logo: 'namecheap',
    backendProvider: 'namecheap',
    supportsCredentialPolling: true,
    capability: 'Read-only domain polling',
    description: 'List domains with a vault credential and an explicitly configured allowlisted egress IP. No IP-discovery service is contacted.',
    credentialExample: '{"api_username":"...","api_key":"...","client_ip":"203.0.113.10","environment":"production"}',
  },
  {
    id: 'ibm_ns1',
    label: 'IBM NS1',
    logo: 'ibm_ns1',
    backendProvider: 'ibm_ns1',
    supportsCredentialPolling: true,
    capability: 'Read-only zone polling',
    description: 'List NS1 zones with a key limited to the View zones permission, through bounded requests to the fixed NS1 service.',
    credentialExample: 'API key or {"api_key":"..."}',
  },
  {
    id: 'aws',
    label: 'AWS WAF',
    logo: 'route53',
    backendProvider: 'aws_waf',
    supportsCredentialPolling: true,
    capability: 'Read-only web ACL polling',
    description: 'List and read AWS WAF web ACLs with an IAM policy limited to two read actions. Route 53 zones are not polled; record them as manual metadata.',
    credentialExample: '{"access_key_id":"...","secret_access_key":"...","region":"us-east-1"}',
  },
  {
    id: 'google_cloud_dns',
    label: 'Google Cloud DNS',
    logo: 'google_cloud',
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'No live polling. Record selected Cloud DNS zone metadata without granting project access.',
  },
  {
    id: 'azure_dns',
    label: 'Azure DNS',
    logo: 'azure',
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'No live polling. Record selected Azure DNS zone metadata without granting subscription access.',
  },
  {
    id: 'hetzner_dns',
    label: 'Hetzner DNS',
    logo: 'hetzner',
    backendProvider: 'generic_waf',
    supportsCredentialPolling: false,
    capability: 'Manual metadata',
    description: 'No live polling. Create a metadata-only provider record and attach operator-supplied DNS zone evidence.',
  },
];

const CREDENTIAL_POLL_BACKENDS = new Set<ProviderBackend>([
  'cloudflare',
  'akamai_edgedns',
  'namecheap',
  'godaddy',
  'ibm_ns1',
  'aws_waf',
]);

const DECLARED_DOMAIN_BEHAVIORS = new Set(['block_at_edge', 'absorb_at_origin', 'rate_shape']);
const TAG_RE = /^[a-z0-9][a-z0-9:_.-]{0,47}$/;

function getDirectoryProvider(id: string) {
  return PROVIDER_DIRECTORY.find((provider) => provider.id === id) ?? PROVIDER_DIRECTORY[0];
}

function connectorDirectoryProvider(connector: DataItem): ProviderDirectoryEntry | null {
  const provider = getString(connector, ['provider'], '').toLowerCase();
  if (provider === 'cloudflare') return getDirectoryProvider('cloudflare');
  if (provider === 'aws_waf') return getDirectoryProvider('aws');
  const direct = PROVIDER_DIRECTORY.find(
    (entry) => entry.backendProvider === provider && entry.backendProvider !== 'generic_waf',
  );
  if (direct) return direct;
  if (provider !== 'generic_waf') return null;
  const config = getNestedItem(connector, ['config']) ?? getNestedItem(connector, ['config_json']);
  const ownerHint = getString(config ?? {}, ['owner_hint'], '').toLowerCase();
  return PROVIDER_DIRECTORY.find((entry) => entry.backendProvider === 'generic_waf' && entry.id === ownerHint) ?? null;
}

function formatConnectorProvider(connector: DataItem) {
  const directoryProvider = connectorDirectoryProvider(connector);
  if (directoryProvider) return directoryProvider.label;
  return getString(connector, ['provider'], 'unrecorded').replaceAll('_', ' ');
}

function connectorHasCredentialPoll(connector: DataItem) {
  const provider = getString(connector, ['provider'], '').toLowerCase() as ProviderBackend;
  return CREDENTIAL_POLL_BACKENDS.has(provider) && Boolean(getString(connector, ['secret_id'], ''));
}

function validateDeclaredHostname(input: string) {
  const hostname = input.trim().toLowerCase().replace(/\.$/, '');
  if (!hostname) return { hostname: '', error: 'Enter a hostname.' };
  if (hostname.length > 253) return { hostname, error: 'Hostname must be 253 characters or fewer.' };
  if (/[\s/:?#@]/.test(hostname)) {
    return { hostname, error: 'Enter a hostname only, without a protocol, port, path, query, or spaces.' };
  }
  const labels = hostname.split('.');
  if (labels.length < 2) return { hostname, error: 'Enter a fully qualified domain name, such as api.example.com.' };
  for (const label of labels) {
    if (!label || label.length > 63) return { hostname, error: 'Each hostname label must contain 1 to 63 characters.' };
    if (!/^[a-z0-9-]+$/.test(label) || label.startsWith('-') || label.endsWith('-')) {
      return { hostname, error: 'Use letters, numbers, and interior hyphens only. International domains must use punycode.' };
    }
  }
  if (/^\d+$/.test(labels[labels.length - 1])) {
    return { hostname, error: 'The final hostname label cannot contain only numbers.' };
  }
  return { hostname, error: '' };
}

function parseTags(input: string): { tags: string[]; error: string } {
  const tags = input
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const deduped = [...new Set(tags)];
  if (deduped.length > 16) return { tags: deduped, error: 'At most 16 tags are allowed.' };
  for (const tag of deduped) {
    if (!TAG_RE.test(tag)) {
      return { tags: deduped, error: `Invalid tag “${tag}”. Use lowercase letters, numbers, and : _ . - (max 48 chars).` };
    }
  }
  return { tags: deduped, error: '' };
}

const NOTIFICATION_CHANNELS_HEADING_ID = 'notification-channels-title';

/** Bring the Notification channels panel into view and move focus to its heading. */
function focusNotificationChannels() {
  const heading = document.getElementById(NOTIFICATION_CHANNELS_HEADING_ID);
  if (!heading) return;
  heading.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
  heading.focus({ preventScroll: true });
}

function ProviderSetupGuidePanel({ provider }: { provider: ProviderDirectoryEntry }) {
  const guide = getProviderSetupGuide(provider.id);
  if (!guide) return <p className="muted">No setup guide is recorded for {provider.label} yet.</p>;
  return (
    <div className="provider-guide">
      <dl className="provider-guide-facts">
        <div>
          <dt>Access mode</dt>
          <dd>
            <Badge tone={guide.mode === 'credential' ? 'success' : 'muted'}>
              {guide.mode === 'credential' ? 'Credential polling' : 'Manual metadata'}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>What AstraNull reads</dt>
          <dd>{guide.reads}</dd>
        </div>
        <div>
          <dt>Minimum permission</dt>
          <dd>{guide.scope}</dd>
        </div>
        {guide.credentialFormat ? (
          <div>
            <dt>Credential format</dt>
            <dd><code>{guide.credentialFormat}</code></dd>
          </div>
        ) : null}
      </dl>
      <div className="provider-guide-section">
        <h3>Steps</h3>
        <ol className="provider-guide-steps">
          {guide.steps.map((step) => <li key={step}>{step}</li>)}
        </ol>
      </div>
      <div className="provider-guide-section">
        <h3>Never performed</h3>
        <p>{guide.never}</p>
      </div>
      <div className="provider-guide-section">
        <h3>Troubleshooting</h3>
        <p>{guide.troubleshooting}</p>
      </div>
      <div className="provider-guide-section">
        <h3>Official documentation</h3>
        <ul className="provider-guide-links">
          {guide.docs.map((link) => (
            <li key={link.href}>
              <a href={link.href} target="_blank" rel="noopener noreferrer">
                {link.label}
                <ExternalLink size={13} aria-hidden="true" />
                <span className="sr-only"> (opens in a new tab)</span>
              </a>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function IntegrationPage({
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
  const { confirm } = useConfirmModal();
  const [selectedConnectorId, setSelectedConnectorId] = useState('');
  const [pendingConnector, setPendingConnector] = useState<DataItem | null>(null);
  const [selectedCreateProviderId, setSelectedCreateProviderId] = useState('cloudflare');
  const [connectorSetupMode, setConnectorSetupMode] = useState<'connect' | 'manual'>('connect');
  const [domainTargetGroupId, setDomainTargetGroupId] = useState('');
  const [showConnectorAdvanced, setShowConnectorAdvanced] = useState(false);
  const [showProviderFlow, setShowProviderFlow] = useState(false);
  const [guideProviderId, setGuideProviderId] = useState('');
  const [showCreateConnector, setShowCreateConnector] = useState(false);
  const [showManualSnapshot, setShowManualSnapshot] = useState(false);
  const [showAddDomain, setShowAddDomain] = useState(false);
  const [domainResult, setDomainResult] = useState<{ hostname: string; groupName: string } | null>(null);
  const [snapshots, setSnapshots] = useState<DataItem[]>([]);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const featureFlags = data.deploymentFeatures as { connectors?: boolean; waf_posture?: boolean } | null;
  const connectorsEnabled = featureFlags?.connectors === true;
  const connectorsLoadError = data.loadErrors.connectors;
  const targetGroupsLoadError = data.loadErrors.targetGroups;
  const canReadConnectors = canReadDataset(session, 'connectors');
  const canReadSecrets = canReadDataset(session, 'secrets');
  const canWriteConnectors = sessionHasPermission(session, 'waf:connector_write');
  const canWriteIntegrationTargets = sessionHasPermission(session, 'target_group:write');
  const canAddIntegration = canWriteConnectors || canWriteIntegrationTargets;
  const canReadNotifications = canReadDataset(session, 'notifications');

  const connectorRecords = pendingConnector
    && !data.connectors.some((connector) => getString(connector, ['id'], '') === getString(pendingConnector, ['id'], ''))
    ? [pendingConnector, ...data.connectors]
    : data.connectors;
  const activeConnectors = connectorRecords.filter(
    (connector) => getString(connector, ['status'], '').toLowerCase() !== 'disabled',
  );
  const selectedConnector =
    activeConnectors.find((connector) => getString(connector, ['id'], '') === selectedConnectorId) ?? activeConnectors[0];
  const effectiveConnectorId = getString(selectedConnector ?? {}, ['id'], '');
  const selectedCreateProvider = getDirectoryProvider(selectedCreateProviderId);
  const guideProvider = guideProviderId ? getDirectoryProvider(guideProviderId) : null;

  const targetGroups = data.targetGroups;
  const effectiveDomainTargetGroupId = targetGroups.some(
    (group) => getString(group, ['id'], '') === domainTargetGroupId,
  )
    ? domainTargetGroupId
    : '';

  function openProviderFlow(providerId = 'cloudflare') {
    if (!canAddIntegration) return;
    setSelectedCreateProviderId(providerId);
    setError('');
    setMessage('');
    setShowProviderFlow(true);
  }

  function beginConnectorSetup(mode: 'connect' | 'manual') {
    if (!canWriteConnectors || !connectorsEnabled) return;
    if (mode === 'connect' && !selectedCreateProvider.supportsCredentialPolling) return;
    setConnectorSetupMode(mode);
    setShowProviderFlow(false);
    setShowCreateConnector(true);
    setError('');
    setMessage('');
  }

  function openAddDomain() {
    if (!canWriteIntegrationTargets) return;
    setShowProviderFlow(false);
    setShowAddDomain(true);
    setDomainResult(null);
    setError('');
    setMessage('');
  }

  function closeAddDomain() {
    if (busy === 'add-single-domain') return;
    setShowAddDomain(false);
    setDomainResult(null);
    setError('');
  }

  async function runAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(formatMutationSuccessMessage(success, result));
      await onRefresh();
      return result;
    } catch (err) {
      setError(apiErrorMessage(err, 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleAddSingleDomain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteIntegrationTargets) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const hostnameResult = validateDeclaredHostname(String(form.get('hostname') ?? ''));
    const expectedBehavior = String(form.get('expected_behavior') ?? '').trim();
    const tagsResult = parseTags(String(form.get('tags') ?? ''));
    const groupId = effectiveDomainTargetGroupId;

    if (hostnameResult.error) {
      setError(hostnameResult.error);
      return;
    }
    if (!DECLARED_DOMAIN_BEHAVIORS.has(expectedBehavior)) {
      setError('Select a supported expected behavior for this domain.');
      return;
    }
    if (tagsResult.error) {
      setError(tagsResult.error);
      return;
    }

    setBusy('add-single-domain');
    setError('');
    setMessage('');
    setDomainResult(null);

    const selectedGroup = targetGroups.find((group) => getString(group, ['id'], '') === groupId) ?? null;
    const resolvedGroupName = groupId
      ? getString(selectedGroup ?? {}, ['name'], groupId)
      : 'the tenant default group';

    try {
      // ADR-0008: POST /v1/targets creates a target directly. An omitted
      // target_group_id lands in the tenant default group (created on demand).
      await requestJson(config, session, '/v1/targets', {
        method: 'POST',
        body: {
          kind: 'fqdn',
          value: hostnameResult.hostname,
          expected_behavior: expectedBehavior,
          ...(tagsResult.tags.length ? { tags: tagsResult.tags } : {}),
          ...(groupId ? { target_group_id: groupId } : {}),
        },
      });
      try {
        await onRefresh();
      } catch {
        // The write is already complete; let the user refresh later.
      }
      setMessage(
        `${hostnameResult.hostname} was added to ${resolvedGroupName}. No provider credentials or inventory discovery were used. Ownership remains unverified.`,
      );
      setDomainResult({ hostname: hostnameResult.hostname, groupName: resolvedGroupName });
      formElement.reset();
    } catch (err) {
      setError(apiErrorMessage(err, 'Could not add the declared domain.'));
    } finally {
      setBusy('');
    }
  }

  async function handleCreateConnector(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteConnectors) return;
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const directoryProvider = getDirectoryProvider(String(form.get('provider') ?? selectedCreateProviderId));
    const credentialSetup = connectorSetupMode === 'connect';
    if (credentialSetup && !directoryProvider.supportsCredentialPolling) {
      setError(`${directoryProvider.label} does not have an implemented credential polling path. Choose Manual metadata instead.`);
      return;
    }
    const provider = directoryProvider.backendProvider;
    const name = String(form.get('name') ?? '').trim();
    const secretInput = credentialSetup ? String(form.get('secret') ?? '').trim() : '';
    const externalSecretId = credentialSetup ? String(form.get('secret_id') ?? '').trim() : '';
    const resourceRefHash = String(form.get('resource_ref_hash') ?? '').trim();
    const region = String(form.get('region') ?? '').trim();
    const awsScope = String(form.get('scope') ?? '').trim().toLowerCase();
    const defaultSnapshotKind = String(form.get('default_snapshot_kind') ?? (provider === 'aws_waf' ? 'waf_policy' : 'dns_zone'));
    if (!name) {
      setError('Connector name is required.');
      return;
    }
    if (credentialSetup && !secretInput && !externalSecretId) {
      setError('Enter a read-only credential or an existing vault secret reference to enable polling.');
      return;
    }
    if (secretInput && externalSecretId) {
      setError('Choose either a new credential or an existing secret reference, not both.');
      return;
    }
    if (secretInput && !(await confirm({
      title: 'Store provider credential',
      description: 'Store this read-only provider credential in the encrypted tenant vault before creating the connector?',
      confirmLabel: 'Store and create',
      confirmTone: 'default',
    }))) return;

    const createdResult = await runAction('create-connector', async () => {
      const connectorBody = {
        provider,
        name,
        status: 'active',
        config: {
          read_only: true,
          connection_mode: credentialSetup ? 'bounded_polling' : 'manual_metadata',
          default_snapshot_kind: defaultSnapshotKind,
          ...(provider === 'generic_waf' ? { owner_hint: directoryProvider.id } : {}),
          ...(provider === 'cloudflare' && resourceRefHash ? { zone_ref_hash: resourceRefHash } : {}),
          ...(provider !== 'cloudflare' && resourceRefHash ? { resource_ref_hash: resourceRefHash } : {}),
          ...(provider === 'aws_waf' && region ? { region_summary: region } : {}),
          ...(provider === 'aws_waf' && (awsScope === 'regional' || awsScope === 'cloudfront') ? { scope: awsScope } : {}),
        },
      };
      let secretId = externalSecretId || null;
      if (secretInput) {
        await requestJson(config, session, '/v1/connectors', {
          method: 'POST',
          body: { ...connectorBody, validate_only: true },
        });
        const stored = await requestJson(config, session, '/v1/secrets', {
          method: 'POST',
          body: {
            purpose: 'connector',
            name: `${provider}:${name}`,
            plaintext: secretInput,
            metadata: { provider, read_only: true, access: 'bounded_metadata_polling' },
          },
        }) as { secret?: { id?: string } };
        secretId = stored.secret?.id ?? null;
      }
      let created: { connector?: DataItem };
      try {
        created = await requestJson(config, session, '/v1/connectors', {
          method: 'POST',
          body: { ...connectorBody, ...(secretId ? { secret_id: secretId } : {}) },
        }) as { connector?: DataItem };
      } catch (err) {
        if (secretInput && secretId) {
          throw new Error(`${err instanceof Error ? err.message : String(err)} The credential was stored as vault secret ${secretId}; retry with that existing secret reference instead of re-entering it.`);
        }
        throw err;
      }
      if (created.connector?.id) {
        setPendingConnector(created.connector);
        setSelectedConnectorId(String(created.connector.id));
      }
      formElement.reset();
      setShowCreateConnector(false);
      return created;
    }, credentialSetup
      ? 'Read-only connector created. Validate it before requesting a provider poll.'
      : 'Manual metadata connector created without provider credentials.');

    if (createdResult && connectorSetupMode === 'manual') {
      setShowManualSnapshot(true);
      setMessage('Manual metadata connector created. Add its first normalized snapshot now; no provider access is used.');
    }
  }

  async function validateConnector(id: string) {
    if (!canWriteConnectors || !id) return;
    await runAction(`validate-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/validate`, { method: 'POST' }), 'Connector validation completed.');
  }

  async function pollConnector(id: string) {
    if (!canWriteConnectors || !id) return;
    const result = await runAction(`poll-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/poll`, { method: 'POST', body: {} }), 'Connector poll requested.');
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
  }

  async function disableConnector(id: string) {
    if (!canWriteConnectors || !id) return;
    if (!await confirm({ title: 'Disable connector', description: 'Disable this connector? Deliveries through it will stop.', confirmLabel: 'Disable connector' })) return;
    await runAction(`disable-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/disable`, { method: 'POST', body: { reason: 'Disabled from integrations page.' } }), 'Connector disabled.');
  }

  async function loadSnapshots(id: string) {
    if (!id) return;
    const result = await runAction(`snapshots-${id}`, () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/snapshots`), 'Connector snapshots loaded.');
    const items = result && typeof result === 'object' && 'items' in result ? (result as { items?: DataItem[] }).items : null;
    setSnapshots(Array.isArray(items) ? items : []);
    setSelectedConnectorId(id);
  }

  async function handleManualSnapshot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canWriteConnectors) return;
    const formElement = event.currentTarget;
    const id = effectiveConnectorId;
    if (!id) {
      setError('Create or select a connector before adding a snapshot.');
      return;
    }
    const form = new FormData(formElement);
    const hostnames = String(form.get('hostnames') ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    const ruleCount = Number(form.get('rule_count') ?? 0);
    const snapshot = {
      snapshot_kind: String(form.get('snapshot_kind') ?? 'waf_policy'),
      display_ref: String(form.get('display_ref') ?? '').trim(),
      resource_ref_hash: String(form.get('resource_ref_hash') ?? '').trim(),
      config_hash: String(form.get('config_hash') ?? '').trim(),
      summary: {
        policy_mode: String(form.get('policy_mode') ?? 'monitor'),
        rule_count: Number.isFinite(ruleCount) ? ruleCount : 0,
        ...(hostnames.length ? { hostnames } : {}),
      },
    };
    if (!snapshot.display_ref || !snapshot.resource_ref_hash || !snapshot.config_hash) {
      setError('Display ref, resource hash, and config hash are required for a metadata snapshot.');
      return;
    }
    const result = await runAction(
      `snapshot-${id}`,
      () => requestJson(config, session, `/v1/connectors/${encodeURIComponent(id)}/poll`, { method: 'POST', body: { manual_only: true, snapshots: [snapshot] } }),
      'Manual connector snapshot ingested.',
    );
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
    if (result) {
      formElement.reset();
      setShowManualSnapshot(false);
    }
  }

  const connectorColumns: TableColumn<DataItem>[] = [
    {
      key: 'name',
      label: 'Connector',
      render: (item) => {
        const directory = connectorDirectoryProvider(item);
        return (
          <div className="connector-name-cell">
            <ProviderLogo provider={directory?.logo ?? 'generic'} size={20} />
            <div className="stack-tight">
              <strong>{getString(item, ['name', 'id'])}</strong>
              <span className="muted small">{formatConnectorProvider(item)}</span>
            </div>
          </div>
        );
      },
    },
    {
      key: 'mode',
      label: 'Capability',
      render: (item) => {
        const hasCredentialPoll = connectorHasCredentialPoll(item);
        return <Badge tone={hasCredentialPoll ? 'success' : 'muted'}>{hasCredentialPoll ? 'Credential polling' : 'Manual metadata'}</Badge>;
      },
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status']);
        return <Badge tone={status === 'active' ? 'success' : status === 'error' ? 'danger' : 'muted'}>{status}</Badge>;
      },
    },
    { key: 'last_poll', label: 'Last poll', render: (item) => formatDate(item.last_polled_at ?? item.last_success_at ?? item.last_poll_at) },
    { key: 'poll_errors', label: 'Poll errors', render: (item) => getOptionalNumber(item, ['consecutive_failures', 'poll_error_count', 'error_count']) ?? <span className="muted">—</span> },
    { key: 'secret', label: 'Secret ref', render: (item) => getString(item, ['secret_id'], 'none — manual only') },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const status = getString(item, ['status'], '').toLowerCase();
        const isDisabled = status === 'disabled';
        const canPoll = connectorHasCredentialPoll(item);
        const rowBusy = busy === `validate-${id}` || busy === `poll-${id}` || busy === `snapshots-${id}` || busy === `disable-${id}`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions row-actions--compact" aria-busy={rowBusy || undefined}>
            {canWriteConnectors ? <Button size="sm" variant="secondary" loading={busy === `validate-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void validateConnector(id)}>Validate</Button> : null}
            {canWriteConnectors ? (
              <Button
                size="sm"
                variant="secondary"
                loading={busy === `poll-${id}`}
                disabled={rowBlocked || isDisabled || !canPoll}
                title={canPoll ? 'Request a bounded read-only provider poll.' : 'Live polling is unavailable; use a manual metadata snapshot.'}
                onClick={() => void pollConnector(id)}
              >
                Poll
              </Button>
            ) : null}
            <Button size="sm" variant="ghost" loading={busy === `snapshots-${id}`} disabled={rowBlocked} onClick={() => void loadSnapshots(id)}>Snapshots</Button>
            {canWriteConnectors ? <Button size="sm" variant="danger" loading={busy === `disable-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void disableConnector(id)}>Disable</Button> : null}
          </div>
        );
      },
    },
  ];

  function providerConnectorCount(provider: ProviderDirectoryEntry) {
    if (!canReadConnectors || connectorsLoadError) return null;
    return connectorRecords.filter((connector) => connectorDirectoryProvider(connector)?.id === provider.id).length;
  }

  const connectedProviderCount = canReadConnectors && !connectorsLoadError
    ? PROVIDER_DIRECTORY.filter((provider) => (providerConnectorCount(provider) ?? 0) > 0).length
    : null;
  const credentialProviderCount = PROVIDER_DIRECTORY.filter((provider) => provider.supportsCredentialPolling).length;

  return (
    <div className="content integration-page">
      <style>{INTEGRATION_TILE_STYLES}</style>
      <style>{INTEGRATIONS_PAGE_STYLES}</style>
      <PageHeader
        route="integrations"
        eyebrow="DNS & edge integrations"
        actions={canAddIntegration ? (
          <>
            {canWriteIntegrationTargets ? (
              <Button variant="default" size="sm" disabled={busy !== ''} onClick={openAddDomain}>
                <Target size={15} aria-hidden="true" /> Add domain
              </Button>
            ) : null}
            <Button variant="secondary" size="sm" disabled={busy !== ''} onClick={() => openProviderFlow()}>
              <PlugZap size={15} aria-hidden="true" /> Add provider
            </Button>
            {connectorsEnabled && canReadConnectors && canWriteConnectors ? (
              <Button
                variant="ghost"
                size="sm"
                disabled={activeConnectors.length === 0 || busy !== '' || Boolean(connectorsLoadError)}
                onClick={() => { setError(''); setMessage(''); setShowManualSnapshot(true); }}
              >
                <FileCheck2 size={15} aria-hidden="true" /> Manual snapshot
              </Button>
            ) : null}
          </>
        ) : undefined}
      />
      <PageContextSummary>Optional enrichment only · no default cloud access · customer-declared targets remain the core path</PageContextSummary>

      <div className="kpi-row" aria-label="Integration inventory summary">
        <div className="kpi-cell">
          <span className="kpi-cell-label">Provider paths</span>
          <span className="kpi-cell-value">{formatNumber(PROVIDER_DIRECTORY.length)}</span>
          <span className="kpi-cell-delta">Read-only or manual metadata</span>
        </div>
        {canReadConnectors ? (
          <>
            <div className="kpi-cell">
              <span className="kpi-cell-label">Connectors</span>
              <span className="kpi-cell-value">{connectorsLoadError ? '—' : formatNumber(connectorRecords.length)}</span>
              <span className="kpi-cell-delta">{connectorsLoadError ? 'Connector status unavailable' : `${activeConnectors.length} active`}</span>
            </div>
            <div className="kpi-cell">
              <span className="kpi-cell-label">Snapshots</span>
              <span className="kpi-cell-value">{connectorsLoadError ? '—' : formatNumber(snapshots.length)}</span>
              <span className="kpi-cell-delta">Normalized metadata only</span>
            </div>
          </>
        ) : (
          <div className="kpi-cell">
            <span className="kpi-cell-label">Connectors</span>
            <span className="kpi-cell-value">—</span>
            <span className="kpi-cell-delta">Not available for your role</span>
          </div>
        )}
        <div className="kpi-cell">
          <span className="kpi-cell-label">Vault secrets</span>
          <span className="kpi-cell-value">{!canReadSecrets || data.loadErrors.secrets ? '—' : formatNumber(data.secrets.length)}</span>
          <span className="kpi-cell-delta">{canReadSecrets ? 'Plaintext never rendered' : 'Not available for your role'}</span>
        </div>
      </div>

      <CalloutNote icon={ShieldCheck} tone="info">
        Provider access is optional. Core validation continues from customer-declared targets, and opening this directory never grants AstraNull cloud access.
      </CalloutNote>

      {!connectorsEnabled ? (
        <CalloutNote icon={PlugZap} tone="warn">
          The connector add-on is not enabled for this tenant, so live provider polling and metadata snapshots are unavailable. You can still declare domains directly with <strong>Add domain</strong>. Contact support to enable optional read-only connectors.
        </CalloutNote>
      ) : null}

      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'} role={error ? 'alert' : 'status'} aria-live="polite">
          {error || message}
        </div>
      )}

      <Card>
        <CardHeader>
          <div className="integration-directory-heading">
            <div>
              <CardTitle id="provider-directory-title">Provider directory</CardTitle>
              <CardDescription className="integration-directory-note">
                Choose an implemented read-only connector, a manual metadata record, or declare one domain directly. Opening a provider never grants AstraNull cloud access. Each card links a least-privilege setup guide.
              </CardDescription>
            </div>
            <div className="integration-directory-meta">
              <Badge tone="info">Optional integrations</Badge>
              <span className="integration-tally">
                {connectedProviderCount === null
                  ? `${formatNumber(credentialProviderCount)} with credential polling`
                  : `${formatNumber(connectedProviderCount)} of ${formatNumber(PROVIDER_DIRECTORY.length)} providers connected`}
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ul className="integration-tile-grid" aria-labelledby="provider-directory-title">
            {PROVIDER_DIRECTORY.map((provider) => {
              const count = providerConnectorCount(provider);
              const credentialPath = provider.supportsCredentialPolling;
              const connected = count !== null && count > 0;
              return (
                <li key={provider.id} className="integration-tile" data-connected={connected || undefined}>
                  <div className="integration-tile-head">
                    <div className="integration-identity">
                      <span className="integration-logo-well">
                        <ProviderLogo provider={provider.logo} size={28} />
                      </span>
                      <div className="integration-tile-name">
                        <strong>{provider.label}</strong>
                        <span>{provider.capability}</span>
                      </div>
                    </div>
                    {connected ? <Badge tone="success">{`${formatNumber(count ?? 0)} configured`}</Badge> : null}
                  </div>
                  <p className="integration-tile-desc">{provider.description}</p>
                  <div className="integration-tile-footer">
                    <span className="integration-chip" data-tone={credentialPath ? 'positive' : 'neutral'}>
                      {credentialPath ? <KeyRound size={13} aria-hidden="true" /> : <FileCheck2 size={13} aria-hidden="true" />}
                      {credentialPath ? 'Credential polling' : 'Manual metadata'}
                    </span>
                    <div className="integration-tile-actions">
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Setup guide for ${provider.label}`}
                        onClick={() => setGuideProviderId(provider.id)}
                      >
                        <BookOpen size={14} aria-hidden="true" /> Setup guide
                      </Button>
                      {canAddIntegration ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={busy !== ''}
                          aria-label={`${credentialPath ? 'Connect' : 'Add'} ${provider.label}`}
                          onClick={() => openProviderFlow(provider.id)}
                        >
                          {credentialPath ? 'Connect' : 'Add manually'}
                        </Button>
                      ) : null}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
          {!canAddIntegration ? (
            <p className="muted small provider-directory-footnote">Connecting providers is read only for your role. Setup guides stay available.</p>
          ) : null}
        </CardContent>
      </Card>

      <FormModal
        open={guideProvider !== null}
        title={guideProvider ? `${guideProvider.label} setup guide` : 'Setup guide'}
        description="Least-privilege, read-only steps verified against the provider's documentation."
        wide
        onClose={() => setGuideProviderId('')}
      >
        {guideProvider ? (
          <>
            <div className="provider-flow-context">
              <div className="integration-identity">
                <span className="integration-logo-well">
                  <ProviderLogo provider={guideProvider.logo} size={28} />
                </span>
                <div className="integration-tile-name">
                  <strong>{guideProvider.label}</strong>
                  <span>{guideProvider.capability}</span>
                </div>
              </div>
            </div>
            <ProviderSetupGuidePanel provider={guideProvider} />
            <div className="form-actions">
              <Button type="button" variant="ghost" onClick={() => setGuideProviderId('')}>Close</Button>
              {canAddIntegration ? (
                <Button
                  type="button"
                  onClick={() => {
                    const id = guideProvider.id;
                    setGuideProviderId('');
                    openProviderFlow(id);
                  }}
                >
                  {guideProvider.supportsCredentialPolling ? 'Connect' : 'Add manually'}
                </Button>
              ) : null}
            </div>
          </>
        ) : null}
      </FormModal>

      {!connectorsEnabled ? null : !canReadConnectors ? (
        <RoleRestrictedCard title="Configured connectors are not available for your role." />
      ) : (
        <>
          <Card className="card--dense">
            <PanelCardHeader
              title="Configured connectors"
              description="Validate connector metadata, run supported credential-backed polls, load snapshots, or disable a record. Plaintext credentials are never rendered."
              trailing={<Badge tone={connectorsLoadError ? 'warn' : 'muted'}>{connectorsLoadError ? 'Unavailable' : `${connectorRecords.length} total`}</Badge>}
            />
            <CardContent>
              <DataTable
                columns={connectorColumns}
                items={connectorRecords}
                loadError={connectorsLoadError}
                onRetry={() => void onRefresh()}
                empty={(
                  <EmptyState
                    icon={PlugZap}
                    title="No connectors configured yet"
                    body={canAddIntegration
                      ? 'Add an optional read-only provider from the directory above, or keep using declared domains and manual evidence. To hear about findings in Slack, Teams, email, or a webhook, set up a notification channel.'
                      : 'An owner or admin can add an optional read-only provider. Declared domains and manual evidence keep working without provider access.'}
                    actionLabel={canAddIntegration ? 'Add provider' : undefined}
                    actionVariant="default"
                    onAction={canAddIntegration ? () => openProviderFlow() : undefined}
                    actions={canReadNotifications ? (
                      <Button type="button" variant="secondary" onClick={focusNotificationChannels}>
                        <BellRing size={15} aria-hidden="true" /> Set up notifications
                      </Button>
                    ) : null}
                  />
                )}
              />
            </CardContent>
          </Card>
          {snapshots.length > 0 ? (
            <Card className="card--dense">
              <PanelCardHeader
                title="Loaded connector snapshots"
                description="Recorded by a supported provider check or manual metadata entry."
                trailing={<Badge tone="muted">{snapshots.length}</Badge>}
              />
              <CardContent className="support-evidence-list">
                {snapshots.map((snapshot) => (
                  <div key={getString(snapshot, ['id'])} className="support-evidence-item">
                    <div className="support-evidence-main">
                      <span className="support-evidence-type">{getString(snapshot, ['snapshot_kind'])}</span>
                      <span className="support-evidence-action">{getString(snapshot, ['display_ref'])}</span>
                    </div>
                    <span className="muted">{formatDate(snapshot.observed_at ?? snapshot.created_at)}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : null}
        </>
      )}

      <NotificationChannelsPanel
        config={config}
        session={session}
        onChanged={onRefresh}
        headingId={NOTIFICATION_CHANNELS_HEADING_ID}
      />

      <FormModal
        open={canAddIntegration && showProviderFlow}
        title={`Configure ${selectedCreateProvider.label}`}
        description="Choose the least-access path that meets your need. A provider selection alone never connects an account."
        wide
        onClose={() => setShowProviderFlow(false)}
      >
        <div className="provider-flow-context">
          <div className="integration-identity">
            <span className="integration-logo-well">
              <ProviderLogo provider={selectedCreateProvider.logo} size={28} />
            </span>
            <div className="integration-tile-name">
              <strong>{selectedCreateProvider.label}</strong>
              <span>{selectedCreateProvider.capability}</span>
            </div>
          </div>
          <label>
            <span>Provider</span>
            <select value={selectedCreateProviderId} onChange={(event) => setSelectedCreateProviderId(event.target.value)}>
              {PROVIDER_DIRECTORY.map((provider) => <option key={provider.id} value={provider.id}>{provider.label}</option>)}
            </select>
          </label>
        </div>
        <div className="provider-path-grid">
          <article className="provider-path">
            <span className="provider-path-icon" aria-hidden="true"><KeyRound size={18} /></span>
            <Badge tone={connectorsEnabled && selectedCreateProvider.supportsCredentialPolling ? 'success' : 'muted'}>
              {!connectorsEnabled ? 'Add-on disabled' : selectedCreateProvider.supportsCredentialPolling ? 'Implemented' : 'Unavailable for this provider'}
            </Badge>
            <h3>Connect read-only</h3>
            <p>Store a vault-backed read-only credential and use the bounded polling worker for Cloudflare, Akamai EdgeDNS, Namecheap, GoDaddy, IBM NS1, or AWS WAF web ACLs.</p>
            <Button
              type="button"
              size="sm"
              disabled={!canWriteConnectors || !connectorsEnabled || !selectedCreateProvider.supportsCredentialPolling}
              onClick={() => beginConnectorSetup('connect')}
            >
              Continue to connect
            </Button>
          </article>
          <article className="provider-path">
            <span className="provider-path-icon" aria-hidden="true"><FileCheck2 size={18} /></span>
            <Badge tone={connectorsEnabled ? 'info' : 'muted'}>{connectorsEnabled ? 'No credentials' : 'Add-on disabled'}</Badge>
            <h3>Manual metadata</h3>
            <p>Create a provider record without credentials, then submit selected normalized zone or policy metadata. AstraNull does not contact the provider.</p>
            <Button type="button" size="sm" variant="secondary" disabled={!canWriteConnectors || !connectorsEnabled} onClick={() => beginConnectorSetup('manual')}>
              Continue manually
            </Button>
          </article>
          <article className="provider-path">
            <span className="provider-path-icon" aria-hidden="true"><Target size={18} /></span>
            <Badge tone="info">Core workflow</Badge>
            <h3>Single domain</h3>
            <p>Declare one FQDN directly. It lands in your chosen or default target group; ownership verification remains required.</p>
            {canWriteIntegrationTargets ? (
              <Button type="button" size="sm" variant="secondary" onClick={openAddDomain}>Add single domain</Button>
            ) : <span className="muted">Domain declaration is read-only for your role.</span>}
          </article>
        </div>
        <details className="disclosure provider-flow-guide">
          <summary>
            <BookOpen size={15} aria-hidden="true" /> {selectedCreateProvider.label} setup guide
          </summary>
          <ProviderSetupGuidePanel provider={selectedCreateProvider} />
        </details>
        <div className="form-actions">
          <Button type="button" variant="ghost" onClick={() => setShowProviderFlow(false)}>Cancel</Button>
        </div>
      </FormModal>

      {connectorsEnabled && canWriteConnectors ? (
        <>
          <FormModal
            open={showCreateConnector}
            title={connectorSetupMode === 'connect' ? `Connect ${selectedCreateProvider.label} read-only` : `Add ${selectedCreateProvider.label} manually`}
            description={connectorSetupMode === 'connect'
              ? 'Creates a vault-backed connector for the implemented bounded metadata poller. Validate it before the first poll.'
              : 'Creates a metadata-only connector. No cloud credential or provider access is requested.'}
            wide
            onClose={() => setShowCreateConnector(false)}
          >
            {error ? <div className="form-banner error" role="alert">{error}</div> : null}
            <form className="product-form" onSubmit={handleCreateConnector} aria-busy={busy === 'create-connector' || undefined}>
              <fieldset disabled={busy !== ''}>
                <label>
                  <span>Provider</span>
                  <select name="provider" value={selectedCreateProviderId} onChange={(event) => setSelectedCreateProviderId(event.target.value)}>
                    {PROVIDER_DIRECTORY.filter((provider) => connectorSetupMode === 'manual' || provider.supportsCredentialPolling).map((provider) => (
                      <option key={provider.id} value={provider.id}>
                        {provider.label} — {provider.supportsCredentialPolling ? provider.capability : 'manual metadata'}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Connector name</span>
                  <input name="name" placeholder={`${selectedCreateProvider.id}-${connectorSetupMode === 'connect' ? 'readonly' : 'manual'}`} required />
                </label>
                {connectorSetupMode === 'connect' ? (
                  <>
                    {getProviderSetupGuide(selectedCreateProvider.id) ? (
                      <div className="full provider-scope-hint">
                        <KeyRound size={15} aria-hidden="true" />
                        <span>
                          <strong>Minimum permission:</strong> {getProviderSetupGuide(selectedCreateProvider.id)?.scope}
                        </span>
                      </div>
                    ) : null}
                    <label className="full">
                      <span>New read-only credential</span>
                      <textarea
                        name="secret"
                        rows={4}
                        placeholder={selectedCreateProvider.credentialExample ?? (selectedCreateProvider.backendProvider === 'aws_waf' ? 'Read-only AWS credential JSON' : 'Read-only provider credential JSON')}
                      />
                    </label>
                    <label className="full">
                      <span>Or existing vault secret ref</span>
                      <input name="secret_id" placeholder="secret_..." />
                    </label>
                    <p className="muted full">Provide one option. New credentials are encrypted in the tenant vault and never shown again. If the operator has not configured the connector vault key, storing a credential fails with an actionable error — use an existing vault secret reference or contact your operator.</p>
                  </>
                ) : (
                  <div className="full">
                    <CalloutNote icon={FileCheck2} tone="info">
                      Manual mode never accepts provider credentials. After creation, add a normalized metadata snapshot with hashes rather than raw provider payloads.
                    </CalloutNote>
                  </div>
                )}
                <details className="full" open={showConnectorAdvanced} onToggle={(event) => setShowConnectorAdvanced((event.currentTarget as HTMLDetailsElement).open)}>
                  <summary>Advanced metadata</summary>
                  <label>
                    <span>Resource hash</span>
                    <input name="resource_ref_hash" placeholder="Optional zone or resource hash" />
                  </label>
                  {selectedCreateProvider.backendProvider === 'aws_waf' ? (
                    <>
                      <label>
                        <span>Web ACL scope</span>
                        <select name="scope" defaultValue="regional">
                          <option value="regional">Regional (ALB, API Gateway, AppSync)</option>
                          <option value="cloudfront">CloudFront (always us-east-1)</option>
                        </select>
                      </label>
                      <label>
                        <span>AWS region</span>
                        <input name="region" placeholder="us-east-1" />
                      </label>
                    </>
                  ) : null}
                  <label>
                    <span>Default snapshot kind</span>
                    <select name="default_snapshot_kind" defaultValue={selectedCreateProvider.backendProvider === 'aws_waf' ? 'waf_policy' : 'dns_zone'}>
                      {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                </details>
                <div className="form-actions full">
                  <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowCreateConnector(false)}>Cancel</Button>
                  <Button loading={busy === 'create-connector'} disabled={busy !== ''} type="submit">
                    {connectorSetupMode === 'connect' ? 'Create read-only connector' : 'Create manual connector'}
                  </Button>
                </div>
              </fieldset>
            </form>
          </FormModal>

          <FormModal
            open={showManualSnapshot}
            title="Manual metadata snapshot"
            description="Use this for generic providers, or whenever credential-backed polling is unavailable. Only normalized metadata is accepted."
            wide
            onClose={() => setShowManualSnapshot(false)}
          >
            {error ? <div className="form-banner error" role="alert">{error}</div> : null}
            {connectorsLoadError && !pendingConnector ? (
              <div className="form-banner error" role="alert">
                <span>Could not load connectors — {connectorsLoadError}</span>
                <Button type="button" size="sm" variant="ghost" onClick={() => void onRefresh()}>Retry</Button>
              </div>
            ) : (
              <form className="product-form" onSubmit={handleManualSnapshot} aria-busy={busy.startsWith('snapshot-') || undefined}>
                <label className="full">
                  <span>Connector</span>
                  <select value={effectiveConnectorId} onChange={(event) => setSelectedConnectorId(event.target.value)} required>
                    {activeConnectors.map((connector) => (
                      <option key={getString(connector, ['id'])} value={getString(connector, ['id'])}>
                        {getString(connector, ['name'])} — {formatConnectorProvider(connector)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Snapshot kind</span>
                  <select name="snapshot_kind" defaultValue="dns_zone">
                    {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>Display ref</span>
                  <input name="display_ref" placeholder="zone-a" required />
                </label>
                <label>
                  <span>Resource hash</span>
                  <input name="resource_ref_hash" placeholder="res_hash_1" required />
                </label>
                <label>
                  <span>Config hash</span>
                  <input name="config_hash" placeholder="cfg_hash_1" required />
                </label>
                <label>
                  <span>Policy mode</span>
                  <select name="policy_mode" defaultValue="monitor">
                    <option value="block">Block</option>
                    <option value="monitor">Monitor</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </label>
                <label>
                  <span>Rule count</span>
                  <input name="rule_count" type="number" min="0" defaultValue="0" />
                </label>
                <label className="full">
                  <span>Hostnames</span>
                  <input name="hostnames" placeholder="app.example.com, api.example.com" />
                </label>
                <div className="form-actions full">
                  <Button type="button" variant="ghost" disabled={busy !== ''} onClick={() => setShowManualSnapshot(false)}>Cancel</Button>
                  <Button loading={busy.startsWith('snapshot-')} disabled={busy !== '' || !effectiveConnectorId} type="submit">Ingest snapshot</Button>
                </div>
              </form>
            )}
          </FormModal>
        </>
      ) : null}

      <FormModal
        open={canWriteIntegrationTargets && showAddDomain}
        title="Add single domain"
        description="Declare one hostname as a target. This is not provider discovery and does not grant cloud access."
        wide
        onClose={closeAddDomain}
      >
        {error ? <div className="form-banner error" role="alert">{error}</div> : null}
        {domainResult ? (
          <div className="domain-result">
            <div className="domain-result-heading">
              <div>
                <h3>{domainResult.hostname} is now declared</h3>
                <p>Target group: {domainResult.groupName}</p>
              </div>
              <Badge tone="warn">Ownership unverified</Badge>
            </div>
            <p>Provenance: manual customer declaration in the AstraNull portal. No provider credentials, account inventory, or automatic discovery were used.</p>
            <div className="form-actions">
              <AnchorButton href="#targets" variant="secondary">View target inventory</AnchorButton>
              <Button type="button" onClick={closeAddDomain}>Done</Button>
            </div>
          </div>
        ) : (
          <form className="product-form" onSubmit={handleAddSingleDomain} aria-busy={busy === 'add-single-domain' || undefined}>
            <fieldset disabled={busy === 'add-single-domain'}>
              <label className="full">
                <span>Hostname</span>
                <input
                  name="hostname"
                  className="mono"
                  placeholder="checkout.example.com"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  inputMode="url"
                  required
                  autoFocus
                />
              </label>
              <label className="full">
                <span>Expected behavior</span>
                <select name="expected_behavior" defaultValue="block_at_edge" required>
                  <option value="block_at_edge">Block at edge</option>
                  <option value="absorb_at_origin">Absorb at origin</option>
                  <option value="rate_shape">Rate shape</option>
                </select>
              </label>
              <label className="full">
                <span>Target group (optional)</span>
                {targetGroupsLoadError ? (
                  <span className="muted small">Target groups unavailable — the domain will land in the tenant default group.</span>
                ) : (
                  <select
                    name="target_group_id"
                    value={effectiveDomainTargetGroupId}
                    onChange={(event) => setDomainTargetGroupId(event.target.value)}
                  >
                    <option value="">Tenant default group</option>
                    {targetGroups.map((group) => {
                      const id = getString(group, ['id'], '');
                      return <option key={id} value={id}>{getString(group, ['name'], id)}</option>;
                    })}
                  </select>
                )}
              </label>
              <label className="full">
                <span>Tags (optional)</span>
                <input name="tags" placeholder="env:production, team:checkout" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
              </label>
              <div className="domain-provenance full">
                <strong>Recorded provenance:</strong> manual customer declaration via AstraNull Integrations; provider access: none. The target starts unverified and cannot receive external probes until ownership is proven.
              </div>
              <div className="form-actions full">
                <Button type="button" variant="ghost" disabled={busy !== ''} onClick={closeAddDomain}>Cancel</Button>
                <Button type="submit" loading={busy === 'add-single-domain'} disabled={busy !== ''}>Add declared domain</Button>
              </div>
            </fieldset>
          </form>
        )}
      </FormModal>
    </div>
  );
}
