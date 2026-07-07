import { useMemo, useState, type ReactNode } from 'react';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Tabs } from '../ui/tabs';
import { agentInstallApiBase } from '../../lib/agent-helpers';
import { resolveAgentReleaseMetadata } from '../../lib/agent-release-metadata';
import type { PortalData } from '../../lib/types';

const INSTALL_TABS = [
  { id: 'linux', label: 'Linux one-liner' },
  { id: 'container', label: 'Container image' },
  { id: 'helm', label: 'Kubernetes/Helm' },
  { id: 'deb', label: 'Debian/Ubuntu' },
  { id: 'rpm', label: 'RHEL/Fedora' },
  { id: 'tarball', label: 'Air-gapped tarball' },
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

function ReleaseMetaField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <span>{label}</span>
      {children}
    </div>
  );
}

function InstallCodeBlock({ tabId, label, code }: { tabId: InstallTabId; label: string; code: string }) {
  return (
    <pre
      className="codeblock"
      id={installPanelId(tabId)}
      role="tabpanel"
      aria-label={`${label} install commands`}
      style={INSTALL_CODE_STYLE}
    >
      {code}
    </pre>
  );
}

function buildInstallSnippet(
  tabId: InstallTabId,
  apiBase: string,
  installToken: string,
  release: ReturnType<typeof resolveAgentReleaseMetadata>
): string {
  switch (tabId) {
    case 'linux':
      return `curl -fsSL ${apiBase}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${apiBase}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`;
    case 'container':
      return `docker run -d --name astranull-agent \\
  -e ASTRANULL_API_URL="${apiBase}" \\
  -e ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" \\
  ${release.packageName}:latest`;
    case 'helm':
      return `helm upgrade --install astranull-agent ./charts/agent \\
  --namespace astranull --create-namespace \\
  --set apiUrl="${apiBase}" \\
  --set image.tag="${release.version}" \\
  --set bootstrapToken="${installToken}"`;
    case 'deb':
      return `curl -fsSL -O ${apiBase}/agents/${release.packageName}_${release.version}_amd64.deb
sudo dpkg -i ${release.packageName}_${release.version}_amd64.deb
sudo install -m 0640 /dev/stdin /etc/astranull/agent.env <<'EOF'
ASTRANULL_API_URL=${apiBase}
ASTRANULL_BOOTSTRAP_TOKEN=${installToken}
EOF
sudo systemctl enable --now astranull-agent`;
    case 'rpm':
      return `curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.noarch.rpm
sudo dnf install ./${release.packageName}-${release.version}.noarch.rpm
sudo systemctl enable --now astranull-agent`;
    case 'tarball':
      return `curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.tar.gz
curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.manifest.json
curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.manifest.sig
# Verify manifest signature, then extract to /opt/astranull`;
    case 'puppet':
      return `class { 'astranull::agent':
  api_url       => '${apiBase}',
  bootstrap     => Sensitive('${installToken}'),
  package_digest => '${release.digest}',
  outbound_only => true,
}`;
    case 'ansible':
      return `- name: Install AstraNull agent
  ansible.builtin.include_role:
    name: astranull.agent
  vars:
    astranull_api_url: "${apiBase}"
    astranull_bootstrap_token: "{{ vault_bootstrap_token }}"
    astranull_package_digest: "${release.digest}"`;
    default:
      return '';
  }
}

export function AgentInstallMatrix({
  data,
  tokenSecret,
  onCreateToken,
  createBusy,
  actionsDisabled
}: {
  data: PortalData;
  tokenSecret: string;
  onCreateToken: () => void;
  createBusy: boolean;
  actionsDisabled: boolean;
}) {
  const [tab, setTab] = useState<InstallTabId>('linux');
  const release = resolveAgentReleaseMetadata(data.releaseEvidence);
  const apiBase = agentInstallApiBase();
  const installToken = tokenSecret || '<BOOTSTRAP_TOKEN>';
  const tabOptions = INSTALL_TABS.map((item) => ({ id: item.id, label: item.label }));
  const activeTab = INSTALL_TABS.find((item) => item.id === tab) ?? INSTALL_TABS[0];

  const snippet = useMemo(
    () => buildInstallSnippet(tab, apiBase, installToken, release),
    [tab, apiBase, installToken, release]
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Deploy an agent</CardTitle>
        <CardDescription>Outbound-only install paths. Release metadata is sourced from production release evidence records.</CardDescription>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="release-metadata-bar kv-list kv-list--compact" aria-label="Agent release metadata">
          <ReleaseMetaField label="Release">
            <strong className="mono" title="From agent_install_matrix / agent_sbom_provenance evidence">
              {release.version}
            </strong>
          </ReleaseMetaField>
          <ReleaseMetaField label="Image digest">
            <strong className="mono" title="Package SHA-256 from SBOM evidence">
              {release.digest}
            </strong>
          </ReleaseMetaField>
          <ReleaseMetaField label="Cosign">
            <strong title="Signature status from release evidence">{release.cosignStatus}</strong>
          </ReleaseMetaField>
          <ReleaseMetaField label="SBOM">
            {release.sbomUri !== '—' ? (
              <AnchorButton size="sm" variant="ghost" href={release.sbomUri} aria-label="Open CycloneDX 1.5 SBOM">
                CycloneDX 1.5
              </AnchorButton>
            ) : (
              <strong>—</strong>
            )}
          </ReleaseMetaField>
          <ReleaseMetaField label="Provenance">
            {release.provenanceUri !== '—' ? (
              <AnchorButton size="sm" variant="ghost" href={release.provenanceUri} aria-label="Open SLSA v1 provenance">
                SLSA v1
              </AnchorButton>
            ) : (
              <strong>—</strong>
            )}
          </ReleaseMetaField>
        </div>
        <div className="row-actions page-toolbar">
          <Button
            loading={createBusy}
            disabled={actionsDisabled}
            onClick={onCreateToken}
            aria-label="Create bootstrap token for agent install"
          >
            Create bootstrap token
          </Button>
        </div>
        <Tabs
          value={tab}
          options={tabOptions}
          onChange={(value) => setTab(value as InstallTabId)}
          className="tabs-wrap"
          getPanelId={installPanelId}
        />
        <InstallCodeBlock tabId={tab} label={activeTab.label} code={snippet} />
        {tokenSecret ? (
          <p className="muted" role="status">
            One-time token shown. It will not be displayed again after refresh.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}