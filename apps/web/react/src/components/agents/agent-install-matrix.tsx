import { useMemo, useState, type ReactNode } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Tabs } from '../ui/tabs';
import { resolveAgentInstallRelease, type AgentInstallRelease } from '../../lib/agent-install-release.mjs';
import type { DataItem } from '../../lib/types';

const INSTALL_TABS = [
  { id: 'tarball', label: 'Signed tarball prep' },
  { id: 'container', label: 'Container image' },
  { id: 'helm', label: 'Kubernetes/Helm' },
  { id: 'deb', label: 'Debian/Ubuntu' },
  { id: 'rpm', label: 'RHEL/Fedora' },
  { id: 'puppet', label: 'Puppet' },
  { id: 'ansible', label: 'Ansible' }
] as const;

type InstallTabId = (typeof INSTALL_TABS)[number]['id'];

const INSTALL_CODE_STYLE = {
  color: 'var(--fg)',
  background: 'color-mix(in oklab, var(--fg), transparent 97%)',
  borderColor: 'var(--border)'
} as const;

function installPanelId(tabId: InstallTabId) {
  return `agent-install-panel-${tabId}`;
}

function shellQuote(value: string) {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function buildDownloadPreparationSnippet(release: AgentInstallRelease | null, tabId: InstallTabId) {
  if (!release || tabId !== 'tarball') return '';
  return `set -eu
umask 077
mkdir -p astranull-agent-download
cd astranull-agent-download

# Fetch each accepted HTTPS URL exactly. curl does not follow redirects; non-2xx responses fail.
download_exact() {
  url="$1"
  output="$2"
  partial="\${output}.partial"
  rm -f "$partial"
  status="$(curl --fail --silent --show-error --proto '=https' \\
    --output "$partial" --write-out '%{http_code}' "$url")" || {
    rm -f "$partial"
    return 1
  }
  case "$status" in
    2??) mv -f "$partial" "$output" ;;
    *)
      rm -f "$partial"
      printf 'Download rejected: %s returned HTTP %s (redirects are not followed).\\n' "$url" "$status" >&2
      return 1
      ;;
  esac
}

download_exact ${shellQuote(release.manifestUrl)} manifest.json
download_exact ${shellQuote(release.signatureUrl)} manifest.json.sig
download_exact ${shellQuote(release.artifactUrl)} ${shellQuote(release.artifactName)}
printf '%s  %s\\n' ${shellQuote(release.digest)} ${shellQuote(release.artifactName)} | sha256sum --check --strict -

read -r -s -p "Paste one-time bootstrap token: " ASTRANULL_TOKEN
printf '\\n'
sudo install -d -m 0700 /var/lib/astranull
sudo install -m 0600 /dev/null /var/lib/astranull/bootstrap-token
if ! printf '%s' "$ASTRANULL_TOKEN" | sudo tee /var/lib/astranull/bootstrap-token >/dev/null; then
  unset ASTRANULL_TOKEN
  exit 1
fi
unset ASTRANULL_TOKEN

# STOP: checksum-verified download and token-file preparation only; the agent is not installed.
# Signature verification is mandatory before extraction or installation. Use trusted Ed25519
# SPKI material whose SHA-256 fingerprint is ${release.signingFingerprint}, then run the agent
# verifier with manifest.json, manifest.json.sig, ${release.artifactName}, and expected version
# ${release.version}. Do not extract or install when signature verification fails.`;
}

function ReleaseMetaField({ label, children }: { label: string; children: ReactNode }) {
  return <div><span>{label}</span>{children}</div>;
}

export function AgentInstallMatrix({
  tokenSecret,
  onCreateToken,
  createBusy,
  canCreateToken = true,
  actionsDisabled,
  updateReleases,
  trustKeys,
  metadataLoading,
  releaseLoadError,
  trustKeyLoadError
}: {
  tokenSecret: string;
  onCreateToken: () => void;
  createBusy: boolean;
  canCreateToken?: boolean;
  actionsDisabled: boolean;
  updateReleases: DataItem[];
  trustKeys: DataItem[];
  metadataLoading: boolean;
  releaseLoadError: string;
  trustKeyLoadError: string;
}) {
  const [tab, setTab] = useState<InstallTabId>('tarball');
  const [copyNotice, setCopyNotice] = useState('');
  const resolution = useMemo(() => {
    if (metadataLoading) return { release: null, reason: 'Loading signed release and trust metadata.' };
    if (releaseLoadError || trustKeyLoadError) {
      return { release: null, reason: [releaseLoadError, trustKeyLoadError].filter(Boolean).join(' ') };
    }
    return resolveAgentInstallRelease(updateReleases, trustKeys);
  }, [metadataLoading, releaseLoadError, trustKeyLoadError, updateReleases, trustKeys]);
  const release = resolution.release;
  const snippet = useMemo(() => buildDownloadPreparationSnippet(release, tab), [release, tab]);
  const activeTab = INSTALL_TABS.find((item) => item.id === tab) ?? INSTALL_TABS[0];

  async function copySnippet() {
    if (!snippet) return;
    try {
      await navigator.clipboard.writeText(snippet);
      setCopyNotice('Download and token-preparation commands copied.');
    } catch {
      setCopyNotice('Copy failed. Select the commands and copy them manually.');
    }
  }

  return (
    <Card className="agent-install-matrix">
      <CardHeader>
        <div>
          <CardTitle>Install an optional observation agent</CardTitle>
          <CardDescription>Prepare signed materials for an outbound-only observer. Core outside-in validation remains agentless; an agent adds internal or origin corroboration.</CardDescription>
        </div>
        <div className="row-actions" aria-label="Agent install safety boundaries">
          <Badge tone="success">Outbound only</Badge>
          <Badge tone="muted">Optional evidence</Badge>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        {release ? (
          <div className="release-metadata-bar kv-list kv-list--compact" aria-label="Accepted signed agent release metadata">
            <ReleaseMetaField label="Release"><strong className="mono">{release.version}</strong></ReleaseMetaField>
            <ReleaseMetaField label="Artifact"><strong className="mono">{release.artifactName}</strong></ReleaseMetaField>
            <ReleaseMetaField label="SHA-256"><strong className="mono" title={release.digest}>{release.digest}</strong></ReleaseMetaField>
            <ReleaseMetaField label="Trust key"><strong className="mono" title={release.signingFingerprint}>{release.signingFingerprint}</strong></ReleaseMetaField>
            <ReleaseMetaField label="Distribution">
              <span className="row-actions">
                <AnchorButton size="sm" variant="ghost" href={release.manifestUrl} aria-label={`Open signed manifest for agent release ${release.version}`}>Manifest</AnchorButton>
                <AnchorButton size="sm" variant="ghost" href={release.signatureUrl} aria-label={`Open detached signature for agent release ${release.version}`}>Signature</AnchorButton>
                <AnchorButton size="sm" variant="ghost" href={release.artifactUrl} aria-label={`Open tarball artifact for agent release ${release.version}`}>Artifact</AnchorButton>
              </span>
            </ReleaseMetaField>
          </div>
        ) : (
          <div className="form-banner neutral" role="status" aria-live="polite">
            Agent download preparation is unavailable. {resolution.reason} Bootstrap token creation does not depend on signed updates or trust keys and remains available.
          </div>
        )}
        <div className="callout info" role="note">
          <span className="callout-icon" aria-hidden="true"><ShieldCheck size={17} /></span>
          <div className="callout-body">
            <p className="callout-title">Observe-only boundary</p>
            <p className="callout-desc">The agent never originates validation traffic, holds cloud credentials, or opens an inbound management port. Verify the accepted signature before extraction. Copying these commands only prepares a verified download on your host; it does not install the agent, and AstraNull performs no installation for you.</p>
          </div>
        </div>
        <div className="row-actions page-toolbar">
          <Button
            loading={createBusy}
            disabled={!canCreateToken || actionsDisabled}
            title={canCreateToken ? undefined : 'Your role cannot create agent bootstrap tokens.'}
            onClick={onCreateToken}
            aria-label="Create one-time bootstrap token for agent download preparation"
          >
            Create bootstrap token
          </Button>
          <Button
            variant="secondary"
            disabled={!snippet}
            onClick={() => void copySnippet()}
            aria-label={`Copy ${activeTab.label.toLowerCase()} commands`}
          >
            Copy commands
          </Button>
        </div>
        <Tabs
          value={tab}
          options={INSTALL_TABS.map((item) => ({ id: item.id, label: item.label }))}
          onChange={(value) => { setTab(value as InstallTabId); setCopyNotice(''); }}
          className="tabs-wrap"
          ariaLabel="Agent installation packages"
          getPanelId={installPanelId}
        />
        {snippet ? (
          <pre
            className="codeblock"
            id={installPanelId(tab)}
            role="tabpanel"
            aria-label={`${activeTab.label} commands`}
            tabIndex={0}
            style={INSTALL_CODE_STYLE}
          >
            {snippet}
          </pre>
        ) : (
          <div id={installPanelId(tab)} role="tabpanel" tabIndex={0} className="form-banner neutral">
            {release
              ? `${activeTab.label} distribution metadata is not published by the accepted release. No commands are available.`
              : 'Commands remain disabled until an active signed tarball release and active tenant-approved trust key are available.'}
          </div>
        )}
        {tokenSecret ? (
          <p className="muted" role="status" aria-live="polite">
            A one-time token is available in the protected token panel. The commands prompt for it interactively and write it to a mode-0600 file; they do not place it in argv.
          </p>
        ) : null}
        {copyNotice ? <p className="muted" role="status" aria-live="polite">{copyNotice}</p> : null}
      </CardContent>
    </Card>
  );
}
