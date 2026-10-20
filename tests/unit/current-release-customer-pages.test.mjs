import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const read = (relative) => readFileSync(new URL(`../../apps/web/react/src/${relative}`, import.meta.url), 'utf8');
const pageComponents = read('pages/page-components.tsx');
const governance = read('pages/governance-pages.tsx');
const detail = read('pages/detail-pages.tsx');
const integrations = read('pages/integrations-page.tsx');
const library = read('pages/vector-library-page.tsx');
const schedules = read('pages/refined/policies-refined.tsx');
const channels = read('components/integrations/notification-channels.tsx');

function between(source, start, end) {
  const from = source.indexOf(start);
  assert.ok(from >= 0, `missing ${start}`);
  const to = end ? source.indexOf(end, from + start.length) : source.length;
  assert.ok(to > from, `missing ${end} after ${start}`);
  return source.slice(from, to);
}

const policyPage = between(pageComponents, 'export function PolicyPage(', 'export function SupportPage(');
const reportsPage = between(pageComponents, 'export function ReportsPage(', 'function expiresAtFromForm(');
const settingsPage = between(pageComponents, 'export function SettingsPage(', 'export function PolicyPage(');
const supportPage = between(pageComponents, 'export function SupportPage(', 'const ENTITLEMENT_FEATURES');
const auditPage = between(governance, 'export function AuditPage(', 'type ReleaseRecordView');
const notificationsPage = between(governance, 'export function NotificationsPage(', 'function summarizeOperationResult(');
const releasePage = between(governance, 'export function ReleaseEvidencePage(', 'export function SocConsolePage(');
const checkDetail = between(detail, 'function CheckDetailPage(', '/** Row activation that opens the shared evidence inspector');
const policyDetail = between(detail, 'function PolicyDetailPage(', 'export function DetailRoutePage(');
const evidenceDetail = between(detail, 'function EvidenceDetailView(', 'function HighScaleDetailView');
const reportDetail = between(detail, 'export function ReportDetailPage(');

describe('current-release customer pages: one presentation', () => {
  it('removes customer design-variant switches from schedules and the check library', () => {
    for (const source of [pageComponents, schedules, library]) {
      assert.doesNotMatch(source, /VariantSwitch|DesignVariantSwitch|useDesignVariant/);
    }
    assert.match(policyPage, /return <PoliciesRefined \{\.\.\.refinedProps\} \/>;/);
  });
});

describe('validation schedules (TF-05, TF-09)', () => {
  it('never projects a next run from cadence; only the server next_run_at is shown', () => {
    assert.doesNotMatch(pageComponents, /derivePolicyNextRun|POLICY_CADENCE_INTERVAL_MS/);
    assert.match(schedules, /const nextRunAt = str\(policy, \['next_run_at'\]\);/);
    assert.match(schedules, /Next run not recorded/);
    assert.doesNotMatch(schedules, /while \(next < now\)/);
  });

  it('explains every non-dispatching state instead of defaulting to Active', () => {
    for (const reason of ['State not recorded', 'No dispatch happens until the schedule is resumed', 'Manual cadence never dispatches automatically', 'Legacy schedule without an exact target', 'is not in the current check catalog', 'SOC-governed']) {
      assert.ok(schedules.includes(reason), reason);
    }
    assert.doesNotMatch(policyPage, /getString\(item, \['state'\], 'active'\)/);
  });

  it('links the named check to that exact check with caller schedule and target context', () => {
    assert.match(schedules, /buildDetailHref\('check-detail', checkId\)\}\$\{policyId \? `&policy=/);
    assert.doesNotMatch(policyPage, /href="#checks"/);
    assert.match(checkDetail, /getRouteParam\('policy'\)/);
    assert.match(checkDetail, /Back to schedule/);
  });

  it('renders schedule times in the recorded IANA timezone and the viewer timezone separately', () => {
    assert.match(schedules, /timeZone: zone/);
    assert.match(schedules, /your time \(\$\{viewerZone\}\)/);
  });

  it('edits only mutable fields and keeps the binding immutable', () => {
    const edit = between(schedules, 'export function ScheduleEditDialog(', 'export function ScheduleActions(');
    assert.match(edit, /method: 'PATCH', body: changed/);
    for (const field of ['target_id', 'target_group_id', 'check_id']) {
      assert.doesNotMatch(edit, new RegExp(`changed\\.${field}`));
    }
    assert.match(edit, /Discard unsaved schedule changes\?/);
  });

  it('offers Pause or Resume only for active or paused schedules and confirms with the exact binding', () => {
    assert.match(schedules, /const canTogglePause = recordedState === 'active' \|\| recordedState === 'paused';/);
    assert.match(schedules, /No run is dispatched to \$\{target\.targetLabel/);
    assert.match(schedules, /cannot be restored from the portal/);
  });
});

describe('check library and check detail (checks, check-detail)', () => {
  it('is target-first with a deep-linkable target and never substitutes another target', () => {
    assert.match(library, /useState\(\(\) => getRouteParam\('target'\)\)/);
    assert.match(library, /No other target was substituted/);
    assert.doesNotMatch(library, /vectors\.length \|\| 721/);
  });

  it('keeps catalog vectors, runnable checks, and target-compatible checks as separate counts', () => {
    for (const label of ['Catalog vectors', 'Runnable checks', 'Fit this target']) assert.ok(library.includes(label), label);
    assert.match(library, /\/v1\/targets\/\$\{encodeURIComponent\(id\)\}\/compatible-checks/);
  });

  it('reads the exact check and server compatibility instead of inferring from the catalog list', () => {
    assert.match(checkDetail, /\/v1\/checks\/\$\{encodeURIComponent\(entityId\)\}/);
    assert.match(checkDetail, /\/v1\/targets\/\$\{encodeURIComponent\(callerTargetId\)\}\/compatible-checks/);
  });

  it('shows the latest result with its target and time and opens evidence in place, not a run page', () => {
    assert.match(checkDetail, /Latest result on|Latest recorded result/);
    assert.doesNotMatch(checkDetail, /detailRowNavProps\('run-detail'/);
    assert.doesNotMatch(policyDetail, /detailRowNavProps\('run-detail'/);
    assert.match(detail, /openEvidenceInspector\(ref, \{ focusKey: ref\.test_run_id \}\)/);
  });
});

describe('reports and report detail (TF-12)', () => {
  it('requires an explicit review and generation never exports or verifies', () => {
    const generate = between(reportsPage, 'async function handleGenerate()', 'return (');
    assert.doesNotMatch(generate, /\/export|custody\/verify/);
    assert.match(reportsPage, /Review before generating/);
    assert.doesNotMatch(generate, /setScopeMode\('tenant'\)/);
  });

  it('sends exact scope arrays only for the chosen mode and omits them for the whole workspace', () => {
    const generate = between(reportsPage, 'async function handleGenerate()', 'return (');
    assert.doesNotMatch(generate, /body\.target_group_ids/);
    assert.match(generate, /if \(scopeMode === 'targets'\) body\.target_ids = \[\.\.\.selectedTargetIds\];/);
    assert.doesNotMatch(generate, /body\.(target_id|target_group_id|group_id|scope)\b/);
    assert.match(generate, /describeReportScopeError\(result\)/);
  });

  it('offers scoped modes and limits only as advertised by the report capabilities', () => {
    assert.match(reportsPage, /getNestedItem\(data\.reportCapabilities \?\? \{\}, \['scope'\]\)/);
    assert.match(reportsPage, /scopeFields\.includes\('target_ids'\)/);
    assert.match(reportsPage, /getOptionalNumber\(scopeCaps, \['max_ids'\]\)/);
    assert.doesNotMatch(pageComponents, /REPORT_SCOPE_LIMIT/);
    assert.match(reportsPage, /scope was not applied and no other domain was selected/);
  });

  it('keeps an unresolved caller ID visible instead of falling back to another record', () => {
    assert.match(reportsPage, /Nothing else was selected in its place\./);
    assert.match(reportsPage, /Remove \{id\}/);
    assert.match(pageComponents, /case 'unknown_target_group'/);
  });

  it('excludes deferred SOC operational report kinds and separates framework mappings', () => {
    assert.match(pageComponents, /const REPORT_DEFERRED_KINDS = new Set\(\['soc'\]\);/);
    assert.match(reportsPage, /It is not a certification or a statement of compliance/);
  });

  it('treats internal audit as a framework mapping and describes every framework', () => {
    const audiences = between(pageComponents, 'const REPORT_AUDIENCE_KINDS', 'const REPORT_FRAMEWORK_DESCRIPTIONS');
    assert.doesNotMatch(audiences, /internal_audit/);
    assert.match(audiences, /Evidence pack for internal or external auditors: run and test IDs, timestamps, approval artifacts, and custody hashes\./);
    assert.match(pageComponents, /const REPORT_FRAMEWORK_KINDS = new Set\(Object\.keys\(REPORT_FRAMEWORK_DESCRIPTIONS\)\);/);
    for (const text of ['Maps evidence to SOC 2 Trust Services Criteria.', 'Maps evidence to ISO/IEC 27001 Annex A controls.', 'Maps evidence to DORA ICT risk and resilience articles.', 'Maps evidence to NIS2 Article 21 security measures.', 'internal-audit control set']) {
      assert.ok(pageComponents.includes(text), text);
    }
    assert.doesNotMatch(reportsPage, /<small>Control mapping<\/small>/);
  });

  it('lists generated reports before the builder and brings a new snapshot into view', () => {
    const order = ['ref={previewRef}', 'title="Generated reports"', 'title="New report"', '<ProtectionValidationReportPanel'];
    const positions = order.map((marker) => reportsPage.indexOf(marker));
    assert.ok(positions.every((value, index) => value >= 0 && (index === 0 || value > positions[index - 1])), positions.join(','));
    assert.match(reportsPage, /Choose an audience below to generate the first snapshot\./);
    assert.match(reportsPage, /preview\.scrollIntoView\(\{ block: 'start', behavior: prefersReducedMotion\(\) \? 'auto' : 'smooth' \}\);/);
    assert.match(reportsPage, /preview\.focus\(\{ preventScroll: true \}\);/);
    assert.match(reportsPage, /Review the snapshot at the top of this page, then export if you need a file\./);
    assert.match(pageComponents, /Declared targets in scope, every finding open at generation, closed findings and recorded runs inside the period\./);
    assert.match(pageComponents, /Findings in this snapshot/);
    assert.match(pageComponents, /Open at generation \(any opened date\)/);
    assert.match(reportsPage, /label: 'Generated', render: \(item\) => <span className="mono">\{formatTimestamp\(/);
    assert.match(pageComponents, /downloaded \$\{formatTimestamp\(record\.exportedAt\)\}/);
    assert.match(pageComponents, /Snapshot frozen \$\{getString\(summary \?\? \{\}, \['as_of'\], ''\) \? formatTimestamp\(/);
  });

  it('keeps one export menu, verifies custody only on an explicit action, and separates live status', () => {
    assert.equal((reportDetail.match(/<ReportExportMenu/g) ?? []).length, 1);
    assert.doesNotMatch(reportDetail, /Export JSON<\/Button>/);
    assert.match(pageComponents, /onClick=\{\(\) => void exporter\.verifyCustody\(\)\}/);
    assert.match(reportDetail, /Current status/);
    assert.match(reportDetail, /entry: 'report', report_id: entityId/);
  });

  it('reads proof only from the frozen snapshot and never borrows a score or live state', () => {
    assert.match(reportDetail, /summary\?\.snapshot_frozen === true/);
    assert.match(reportDetail, /getNestedArray\(summary, \['runs_snapshot'\]\)/);
    assert.match(reportDetail, /summary\?\.evidence_ids/);
    assert.match(reportDetail, /nothing is filled in from current data/);
    assert.match(reportDetail, /readiness_score_status/);
  });
});

describe('evidence artifact detail', () => {
  it('never links a finding by run proximity and returns to a real route', () => {
    assert.doesNotMatch(evidenceDetail, /byRun/);
    assert.doesNotMatch(detail, /href: '#evidence'/);
  });

  it('distinguishes recorded hash, local computation, and server verification', () => {
    assert.match(evidenceDetail, /primary', 'integrity'/);
    assert.doesNotMatch(evidenceDetail, /getString\(entity, \['verified'\]/);
    for (const label of ['Recorded hash', 'Locally computed (this page)', 'Server verification', 'Not verified (recorded hash only)']) {
      assert.ok(evidenceDetail.includes(label), label);
    }
    assert.match(evidenceDetail, /this is a read failure, not missing evidence/);
  });
});

describe('audit log (TF-13)', () => {
  it('selects an exact incoming event from the shared inspector address or event parameter', () => {
    assert.match(governance, /parseInspectorRef\(window\.location\.hash\)/);
    assert.match(governance, /readAuditParam\('event'\)/);
    assert.match(auditPage, /does not exist in this workspace\. Nothing else was selected in its place\./);
  });

  it('labels hashes as recorded, not verified, and filters by date, actor, action, and resource', () => {
    assert.match(auditPage, /label: 'Recorded hash'/);
    assert.match(auditPage, /does not verify the hash chain/);
    assert.match(auditPage, /auditListQuery\(applied, currentCursor\)/);
    for (const name of ['actor', 'action', 'resource', 'since', 'until', 'cursor', 'limit']) assert.match(governance, new RegExp(`params\\.set\\('${name}'`), name);
    assert.match(auditPage, /type="date"/);
    assert.match(auditPage, /category: applied\.action \|\| null,\n\s+resource: applied\.resource \|\| null,\n\s+from: applied\.since \|\| null,\n\s+to: applied\.until \|\| null/);
  });

  it('pages with the server cursor and reports the server total instead of a client window', () => {
    assert.match(auditPage, /getString\(payload, \['next_cursor'\], ''\)/);
    assert.match(auditPage, /typeof payload\?\.total === 'number'/);
    assert.doesNotMatch(auditPage, /slice\(0, 200\)|data\.auditLog/);
  });
});

describe('support (TF-14)', () => {
  it('offers exact event links only to audit-readable roles and sends nothing', () => {
    assert.match(supportPage, /canReadAuditEvents \? \(/);
    assert.match(supportPage, /#audit\?event=\$\{encodeURIComponent\(ref\.id\)\}/);
    assert.doesNotMatch(supportPage, /requestJson|method: 'POST'/);
    assert.doesNotMatch(supportPage, /href="#runs"/);
  });

  it('falls back to the workspace administrator for members only and refuses to copy credential-like notes', () => {
    assert.match(supportPage, /No support channel is configured for this deployment/);
    assert.match(supportPage, /looks like it contains a credential/);
  });

  it('never sends an owner back to a workspace or deployment administrator they already are', () => {
    const ownerBranch = between(supportPage, ') : ownerView ? (', ') : (');
    assert.match(ownerBranch, /No support channel is published for this deployment\. Ask the team that operates this AstraNull deployment to publish a support contact/);
    assert.doesNotMatch(ownerBranch, /workspace administrator|deployment administrator/);
    const users = between(settingsPage, '<CardTitle>Users and sign-in</CardTitle>', '</Card>');
    assert.match(users, /Inviting users, changing roles, and SSO mapping are handled by your AstraNull account team\./);
    assert.match(users, />Contact support</);
    assert.doesNotMatch(users, /workspace administrator|deployment administrator/);
  });

  it('reads a published https or email support channel and never hard-codes a vendor address', () => {
    const resolver = between(pageComponents, 'export function configuredSupportUri(', 'function isWorkspaceOwnerRole(');
    for (const key of ['support_uri', 'support_url', 'contact_url', 'support_email', 'support_contact_email', 'contact_email']) {
      assert.ok(pageComponents.includes(`'${key}'`), key);
    }
    assert.match(resolver, /parsed\.protocol === 'https:'/);
    assert.doesNotMatch(resolver, /http:'/);
    assert.match(resolver, /href: `mailto:\$\{candidate\}`/);
    assert.doesNotMatch(pageComponents, /support@astranull|@checkred\./i);
  });

  it('publishes probe traffic facts for SOC and WAF teams without hard-coded addresses', () => {
    assert.match(supportPage, /title="Probe traffic"/);
    assert.match(supportPage, /AstraNull signed public probe workers/);
    assert.match(supportPage, /User-Agent containing "AstraNull", but some check phases vary or omit headers/);
    assert.match(supportPage, /config\.siteConfig\?\.probe_source_ranges/);
    assert.match(supportPage, /ask your AstraNull operator/);
    assert.match(supportPage, />\s*Copy probe traffic facts\s*</);
    assert.doesNotMatch(supportPage, /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  });

  it('shows the recorded event time with its source and never treats a legacy alias as authoritative silently', () => {
    assert.match(supportPage, /\['timestamp_source'\]/);
    assert.match(supportPage, /\(legacy time field\)/);
    assert.match(supportPage, /Time not recorded/);
    assert.match(supportPage, /\['as_of_source'\]/);
  });
});

describe('notifications and channels (TF-11)', () => {
  it('opens the failed attempt with its own channel configuration link', () => {
    assert.match(notificationsPage, /#integrations\?focus=\$\{encodeURIComponent\(getString\(selected\.rule, \['id'\], ''\)\)\}/);
    assert.match(channels, /get\('focus'\)/);
    assert.match(notificationsPage, /replaceRouteParams\(\{ focus: selectedAttemptKey \|\| null \}\)/);
    assert.match(notificationsPage, /Channel removed or not recorded/);
  });

  it('treats a channel and its routing as one object and only adds events to an existing channel', () => {
    assert.match(governance, /from '\.\.\/lib\/notification-channels\.mjs'/);
    assert.doesNotMatch(governance, /const NOTIFICATION_TRIGGERS = \[|NOTIFICATION_TRIGGER_LABELS|NOTIFICATION_CHANNEL_OPTIONS/);
    assert.match(notificationsPage, /\{NOTIFICATION_TRIGGER_OPTIONS\.map\(\(option\) => \(/);
    assert.doesNotMatch(notificationsPage, /trigger !== 'high_scale\.state_change'/);
    assert.doesNotMatch(notificationsPage, /New destination|ruleMode|method: 'POST',\s*body: \{ channel/);
    assert.match(notificationsPage, /method: 'PATCH',\s*body: \{ triggers: merged, enabled: ruleEnabled \}/);
    assert.match(notificationsPage, /Choose events for a channel/);
    assert.match(notificationsPage, />Add events</);
    assert.match(notificationsPage, /Set up a channel in Integrations/);
    assert.match(notificationsPage, /title="Channels" description="Each channel receives the events chosen for it\. Set up, turn on or off, and remove channels in Integrations\."/);
    assert.match(notificationsPage, /title="No channels yet\."/);
    assert.match(notificationsPage, /canWrite && \(events\.length > 0 \|\| eventsUnavailable\)/);
    assert.match(channels, /Event routing for existing channels and failed deliveries are on <a href="#notifications">Notifications<\/a>\./);
    assert.match(channels, /id: 'in_app',\s*label: 'In-app'/);
    assert.match(channels, /body: \{ channel: IN_APP_CHANNEL\.id, destination: '', triggers: triggerCheck\.triggers, enabled \}/);
  });

  it('requires a preview before an explicit retry and never retries scheduled or unknown attempts', () => {
    assert.match(notificationsPage, /disabled=\{busy !== '' \|\| retryPreview\?\.key !== selected\.key\}/);
    assert.match(notificationsPage, /No manual retry is offered, to avoid sending twice/);
    assert.match(notificationsPage, /The outcome is unknown, so retry is not offered/);
    assert.doesNotMatch(notificationsPage, /DLQ/);
  });

  it('keeps configured, enabled, attempted, and delivered distinct', () => {
    assert.match(channels, /label: 'Last attempt'/);
    assert.match(channels, /'Enabled' : 'Disabled'/);
    assert.match(notificationsPage, /Recorded, not sent/);
  });
});

describe('integrations (TF-10)', () => {
  it('does not present a configuration check as credential validation and confirms live polls', () => {
    assert.match(integrations, /Check configuration/);
    assert.match(integrations, /Does not contact the provider/);
    assert.match(integrations, /bounded read-only requests were sent with the stored credential/);
    assert.match(integrations, /\{canWriteConnectors && canPoll \? \(/);
    assert.match(integrations, /\{canWriteConnectors && !canPoll \? \(/);
    assert.match(integrations, /onClick=\{\(\) => openManualSnapshot\(id\)\}/);
    assert.match(integrations, />\s*Add snapshot\s*</);
    assert.doesNotMatch(integrations, /Deliveries through it will stop/);
    assert.match(integrations, /label: 'Last successful sync'/);
  });

  it('derives a connector last attempt only from recorded outcomes, never updated_at or poll requests', () => {
    const column = between(integrations, 'const renderConnectorLastAttempt', 'const connectorColumns');
    assert.match(column, /hasOwnProperty\.call\(item, 'last_error_at'\)\) return <span className="muted">Not recorded<\/span>/);
    assert.match(column, /Date\.parse\(failure\) > Date\.parse\(success\)/);
    assert.match(between(integrations, "key: 'last_success'", "key: 'actions'"), /if \(!connectorHasCredentialPoll\(item\)\) return <span className="muted">Not applicable<\/span>;/);
    assert.doesNotMatch(column, /updated_at|last_poll_requested_at|last_polled_at|last_poll_at/);
  });

  it('labels provider cards by connector mode and derives manual snapshot hashes when blank', () => {
    assert.match(integrations, /`\$\{formatNumber\(total\)\} configured · manual`/);
    assert.match(integrations, /`\$\{formatNumber\(total\)\} configured · \$\{formatNumber\(manual\)\} manual`/);
    assert.match(integrations, /<Badge tone="muted">\{providerConfiguredLabel\(provider\)\}<\/Badge>/);
    assert.match(integrations, /Advanced: supply your own hashes/);
    assert.match(integrations, /\.\.\.\(resourceRefHash \? \{ resource_ref_hash: resourceRefHash \} : \{\}\)/);
    assert.match(integrations, /Display ref is required for a metadata snapshot\./);
    assert.doesNotMatch(integrations, /name="resource_ref_hash" placeholder="res_hash_1" required|name="config_hash" placeholder="cfg_hash_1" required/);
  });

  it('guards dirty setup dialogs and never keeps typed credentials', () => {
    assert.match(integrations, /Any credential you typed is cleared and never stored/);
    assert.doesNotMatch(integrations, /localStorage|sessionStorage/);
  });
});

describe('settings (TF-15)', () => {
  it('requires acknowledgement before dismissing a one-time secret and never persists it', () => {
    assert.match(settingsPage, /I have stored this secret somewhere safe/);
    assert.match(settingsPage, /disabled=\{!secretAcknowledged\}/);
    assert.doesNotMatch(settingsPage, /localStorage|sessionStorage/);
  });

  it('states rotation and revocation impact for the exact account', () => {
    assert.match(settingsPage, /stops working immediately/);
    assert.match(settingsPage, /requireTypedId: name/);
  });

  it('validates retention units and constraints and reviews reductions before saving', () => {
    assert.match(settingsPage, /must be a whole number of days from/);
    assert.match(settingsPage, /retentionReductions/);
    assert.match(settingsPage, /Deleted records cannot be recovered/);
  });

  it('describes exactly what each retention period purges and warns only for purging rows', () => {
    assert.match(settingsPage, /Deletes events, evidence vault entries, notification history, connector poll data, and origin clues and saved collection responses older than this\./);
    assert.match(settingsPage, /Generated report snapshots are kept for this period or the metadata period, whichever is longer\./);
    assert.match(settingsPage, /Recorded as your retention policy\. Audit logs are never purged automatically\./);
    assert.match(settingsPage, /Recorded as your retention policy\. SOC authorization packs are never purged automatically\./);
    assert.match(settingsPage, /Only metadata and reports are purged by these settings\. Audit logs, findings, test runs, and SOC authorization artifacts are always kept\./);
    assert.match(settingsPage, /audit_log_days, purges: false/);
    assert.match(settingsPage, /change\.purges && change\.before !== null/);
    assert.doesNotMatch(settingsPage, /separate production retention gates|applies to events, evidence vault, reports/);
  });

  it('picks service-account scopes from the role contract instead of free text', () => {
    assert.match(pageComponents, /from '\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/src\/contracts\/roles\.mjs'/);
    assert.match(pageComponents, /const EXCLUDED_SCOPE_PREFIXES = \['target_group:', 'environment:'\];/);
    assert.match(pageComponents, /const DEFAULT_SERVICE_ACCOUNT_SCOPES = \['tenant:read', 'evidence:read'\];/);
    assert.match(settingsPage, /Only permissions the selected role holds are listed\. Grant the fewest needed\./);
    assert.match(settingsPage, /Select at least one scope\./);
    assert.match(settingsPage, /Create high-privilege service account\?/);
    assert.match(settingsPage, /type="checkbox" name="scopes"/);
    assert.doesNotMatch(settingsPage, /\[a-z_\]\+:\[a-z_\]\+|\['tenant:read'\];|Comma-separated resource:action/);
  });

  it('shows the sign-in method in plain words and hides deployment internals from customers', () => {
    for (const label of ['Single sign-on (OIDC)', 'Developer validation (non-production)', 'Managed by your deployment administrator', 'Sign-in method']) {
      assert.ok(pageComponents.includes(label), label);
    }
    assert.match(settingsPage, /\{oidcPosture\.issuerHost \? </);
    assert.match(settingsPage, /\{showSignInInternals \? <div><span>Login URL<\/span>/);
    assert.match(settingsPage, /Read-only sign-in configuration for this workspace\./);
    assert.doesNotMatch(settingsPage, /Not exposed on public readiness endpoints|`oidc-jwt`|`auth_mode`|>Auth mode</);
    assert.match(settingsPage, /Append-only, hash-chained security history lives on the Audit page/);
    assert.doesNotMatch(settingsPage, /Immutable security-relevant history/);
  });
});

describe('plan and usage', () => {
  it('no longer ships a customer Plan & usage page', () => {
    assert.doesNotMatch(pageComponents, /export function SubscriptionPage\(|SUBSCRIPTION_PAGE_STYLES|title="Plan & usage"/);
  });
});

describe('release evidence', () => {
  it('lists every missing kind and keeps accepted-but-invalid separate from validity and signoff', () => {
    assert.doesNotMatch(releasePage, /slice\(0, 12\)/);
    assert.match(releasePage, /Accepted but invalid/);
    for (const label of ['Inventory', 'Contract validity', 'External signoff']) assert.ok(releasePage.includes(label), label);
    assert.match(releasePage, /Why it fails/);
  });
});

describe('SOC console without an execution tenant', () => {
  const socPage = between(governance, 'export function SocConsolePage(');
  const gates = between(governance, 'function buildSocGoNoGoGates(', 'function providerNameForRequest(');

  it('never reports a clear kill switch or idle gates without the tenant recorded state', () => {
    assert.match(gates, /if \(!context\.tenantSelected\) \{[\s\S]*?tone: 'muted', status: 'Tenant not selected'/);
    assert.match(socPage, /tenantSelected: !executionTenantMissing/);
    assert.match(socPage, /Select an execution tenant to read its kill-switch state\./);
    assert.match(socPage, /executionTenantMissing \? \(\s*<KpiCell label="Kill switch" value="—" delta="Select a tenant" tone="muted" \/>/);
    assert.match(socPage, /<Badge tone="muted">Tenant not selected<\/Badge>/);
    assert.match(socPage, /getString\(data\.state\?\.kill_switch as DataItem, \['reason'\], ''\)/);
    assert.doesNotMatch(governance, /tenant-scoped emergency stop'\)/);
    assert.match(socPage, /Select an execution tenant to compute pre-flight gates\./);
  });
});

describe('SOC console kill switch', () => {
  const socPage = between(governance, 'export function SocConsolePage(');

  it('uses Active and Clear everywhere and never Armed or Inactive', () => {
    assert.doesNotMatch(governance, /'Armed'|'Inactive'/);
    assert.match(socPage, /<KpiCell label="Kill switch" value=\{killSwitchActive \? 'Active' : 'Clear'\}/);
    assert.match(governance, /\{active \? 'Active' : 'Clear'\}<\/Badge>/);
    assert.match(governance, /status: context\.killSwitchActive \? 'Active' : 'Clear'/);
  });

  it('requires a typed reason, names the tenant and running requests, and sends the reviewer text', () => {
    assert.match(socPage, /Reason \(recorded in audit and shown to the tenant\)/);
    assert.match(governance, /const KILL_SWITCH_REASON_MIN = 8;/);
    assert.match(socPage, /maxLength=\{KILL_SWITCH_REASON_MAX\}/);
    assert.match(socPage, /title: `Activate kill switch for \$\{tenantLabel\}`/);
    assert.match(socPage, /title: `Clear kill switch for \$\{tenantLabel\}`/);
    assert.match(socPage, /running high-scale \$\{pluralize\(runningCount, 'request'\)\} will be stopped/);
    assert.match(socPage, /Reason: \$\{reason\}/);
    assert.match(socPage, /body: \{ active, reason \}/);
    assert.doesNotMatch(governance, /SOC console activation|SOC console cleared/);
    assert.match(socPage, /setKillSwitchReasonDraft\(''\);/);
  });

  it('gives Activate full danger weight and keeps Clear small and secondary', () => {
    assert.match(socPage, /<Button\s+variant="danger"\s+loading=\{busy === 'kill-on'\}[\s\S]*?>Activate kill switch<\/Button>/);
    assert.match(socPage, /<Button\s+size="sm"\s+variant="secondary"\s+loading=\{busy === 'kill-off'\}[\s\S]*?>Clear<\/Button>/);
  });

  it('reports what activation stopped and explains the sequence in plain labels', () => {
    assert.match(governance, /Kill switch engaged by \$\{operator\} at \$\{at\}\. Stopped/);
    assert.match(governance, /killSwitchIdList\(item, 'stopped_request_ids'\)/);
    assert.match(governance, /killSwitchIdList\(item, 'cancelled_run_ids'\)/);
    assert.match(socPage, /buildDetailHref\('queue-detail', id, effectiveSocTenant \? \{ tenantId: effectiveSocTenant \} : \{\}\)/);
    assert.match(socPage, /What activation does · \{KILL_SWITCH_SEQUENCE\.length\} steps/);
    assert.match(governance, /probe_fleet_stops_leasing: 'Probe fleet stops leasing work'/);
    assert.match(socPage, /<strong title=\{step\}>\{KILL_SWITCH_STEP_LABELS\[step\]\}<\/strong>/);
    assert.doesNotMatch(governance, /Validated emergency-stop sequence|custody-recorded/);
  });

  it('puts the staff tenant controls first and lets a cross-tenant row pick or stop a tenant', () => {
    const order = ['<CardTitle>Execution tenant</CardTitle>', '{staffSocSurface ? controls : null}', '<div className="kpi-row"', '<PageContextSummary>'];
    const positions = order.map((marker) => socPage.indexOf(marker));
    assert.ok(positions.every((value, index) => value >= 0 && (index === 0 || value > positions[index - 1])), positions.join(','));
    assert.match(socPage, /Choose a tenant here, or use Work on tenant on a row in Cross-tenant execution\./);
    assert.match(socPage, /aria-label=\{`Engage kill switch for \$\{tenantLabel\}`\}/);
    assert.match(socPage, />\s*Work on tenant\s*</);
    assert.match(socPage, /!effectiveSocTenant && crossTenantIds\.length === 1/);
    assert.match(socPage, /onClick=\{\(\) => void applyExecutionTenant\(suggestedExecutionTenant\)\}/);
    assert.doesNotMatch(socPage, /useEffect\(\(\) => \{\s*if \(!staffSocSurface \|\| !isSoc \|\| effectiveSocTenant/);
  });

  it('never carries a kill switch reason from one execution tenant to another', () => {
    assert.match(socPage, /if \(nextTenant !== effectiveSocTenant\) setKillSwitchReasonDraft\(''\);/);
    assert.match(socPage, /useEffect\(\(\) => \{\s*setKillSwitchReasonDraft\(''\);\s*\}, \[effectiveSocTenant\]\);/);
    assert.doesNotMatch(socPage, /key: 'kind', label: 'Kind'/);
    assert.match(governance, /<Badge tone="warn">Window passed<\/Badge>/);
  });

  it('offers quick approval only for reviewable requests and names what is approved', () => {
    assert.match(socPage, /const reviewable = \['submitted', 'under_review'\]\.includes\(state\);/);
    assert.match(socPage, /short: 'Pack not accepted'/);
    assert.match(socPage, /short: 'Select a tenant'/);
    assert.match(socPage, /for tenant \$\{tenantDisplayName\(tenantId\)\} and move it to approved/);
    assert.doesNotMatch(socPage, /schedule: `Schedule high-scale request|start: `Start high-scale execution/);
    assert.match(governance, /governedLimitDisplay,[\s\S]*requestDomainDisplay,[\s\S]*scheduledWindowState[\s\S]*from '\.\.\/lib\/high-scale'/);
    assert.doesNotMatch(governance, /function governedLimitDisplay|function requestDomainDisplay/);
  });

  it('labels Go/No-Go gates honestly and states a verdict', () => {
    assert.match(governance, /kill: 'Tenant kill switch'/);
    assert.match(governance, /execution: 'Running governed tests'/);
    assert.match(governance, /'Go for scheduled requests'/);
    assert.match(governance, /`No-Go · \$\{reasons\}`/);
  });
});

describe('schedule creation expected verdicts', () => {
  it('uses the plain expected-verdict wording and limits observation-only checks to manual review', () => {
    assert.match(pageComponents, /const POLICY_VERDICT_OPTIONS: SelectOption\[\] = Object\.entries\(EXPECTED_VERDICT_LABELS as Record<string, string>\)/);
    assert.match(pageComponents, /\.map\(\(\[value, label\]\) => \(\{ value, label, description: value \}\)\);/);
    assert.match(policyPage, /const policyCheckObservationOnly = selectedPolicyChecks\.length > 0 && selectedPolicyChecks\.every\(isObservationOnlyCheck\);/);
    assert.match(policyPage, /expected_verdict: isObservationOnlyCheck\(check\) \? OBSERVATION_ONLY_VERDICT : policyExpectedVerdict/);
    assert.match(policyPage, /option\.value === OBSERVATION_ONLY_VERDICT/);
    assert.doesNotMatch(policyPage, /description: `\$\{option\.value\} · /);
    assert.match(policyPage, /setPolicyExpectedVerdict\(OBSERVATION_ONLY_VERDICT\)/);
    assert.match(policyPage, /useState\('pass'\)/);
    assert.match(policyPage, /verdictOptions: policyVerdictOptions,/);
    assert.match(policyPage, /`Created \$\{successes\.length\} of \$\{policyBindings\.length\} schedules\. `/);
    assert.doesNotMatch(policyPage, /policies\. `/);
  });
});

describe('staff admin console decisions', () => {
  const staffPage = between(pageComponents, 'export function StaffSurfacePage(');

  it('records the reviewer reason and names what is approved or rejected', () => {
    assert.doesNotMatch(pageComponents, /React staff console/);
    assert.match(staffPage, /const \{ confirm, confirmWithReason \} = useConfirmModal\(\);/);
    assert.match(staffPage, /Approve signup for \$\{organization\} \(requested plan: \$\{plan\}\)\? A tenant account will be provisioned\./);
    assert.match(staffPage, /title: `Reject signup for \$\{organization\}\?`/);
    assert.match(staffPage, /label: 'Reason \(shown to the applicant\)', required: true/);
    assert.match(staffPage, /title: `Approve \$\{kind\} request for tenant \$\{tenant\}\?`/);
    assert.match(staffPage, /body: \{ decision, reason \}/);
    assert.match(staffPage, /onClick=\{\(\) => void approveSignup\(item\)\}/);
    assert.match(staffPage, /onClick=\{\(\) => void decideApproval\(item, 'reject'\)\}/);
    assert.match(staffPage, /name="support_owner_reason"/);
    assert.match(staffPage, /body: \{ support_owner: owner, reason \}/);
  });

  it('names the tenant on entitlement grants and uses one selected-tenant control', () => {
    assert.match(staffPage, /title: `Grant \$\{featureLabel\} to \$\{tenantName\}\?`/);
    assert.match(staffPage, /\$\{tenantName\} \(\$\{entitlementTenantId\}\) gets this access immediately\./);
    assert.match(staffPage, /title: `Revoke \$\{featureLabel\} from \$\{tenantName\}\?`/);
    assert.equal((staffPage.match(/options=\{internalTenantOptions\}/g) ?? []).length, 1);
    assert.match(staffPage, /label="Selected tenant"/);
    assert.match(pageComponents, /export const ENTITLEMENT_FEATURE_LABELS/);
  });

  it('keeps the admin tab in the address and avoids repeating the overview KPIs', () => {
    assert.match(staffPage, /useState\(\(\) => getHashQueryParam\('tab'\) \|\| 'overview'\)/);
    assert.match(staffPage, /replaceRouteParams\(\{ tab: next === 'overview' \? null : next \}\)/);
    assert.match(staffPage, /onChange=\{selectAdminTab\}/);
    assert.match(staffPage, /\{isStaff && activeAdminTab !== 'overview' \? \(\s*<PageContextSummary>/);
    assert.match(staffPage, /formatAuditAction\(getString\(item, \['action'\], ''\), 'Unknown action', item\.metadata\)/);
    assert.match(staffPage, /plainCodeLabel\(getString\(item, \['lifecycle_state'\], ''\), 'Not recorded'\)/);
    assert.match(staffPage, /plainCodeLabel\(getString\(item, \['kind'\], ''\), 'Not recorded'\)/);
  });
});

describe('audit log filters and export', () => {
  it('maps typed labels back to stored keys and offers labelled options', () => {
    assert.match(governance, /export function resolveAuditFilterKey\(typed: string, labels: ReadonlyMap<string, string>\)/);
    assert.match(governance, /if \(!value \|\| value\.includes\('\.'\)\) return value;/);
    assert.match(auditPage, /action: resolveAuditFilterKey\(next\.action, actionLabelKeys\)/);
    assert.match(auditPage, /resource: resolveAuditFilterKey\(next\.resource, resourceLabelKeys\)/);
    assert.match(auditPage, /AUDIT_ACTIONS\.map\(\(entry\) => entry\.value\)/);
    assert.match(auditPage, /<option key=\{value\} value=\{value\} label=\{formatAuditAction\(value\)\} \/>/);
    assert.match(auditPage, /placeholder="Choose or type an action"/);
    assert.match(auditPage, /<span>Actor \(user ID\)<\/span>/);
    assert.match(auditPage, /Type the action or resource as shown, or its key; filters match exactly\./);
    for (const label of ['Filter to this actor', 'Filter to this action', 'Filter to this resource']) assert.ok(auditPage.includes(label), label);
    assert.match(auditPage, /formatAuditAction\(getString\(item, \['action'\]\), 'Unknown action', item\.metadata\)/);
    assert.match(auditPage, /formatAuditAction\(getString\(selectedEntry, \['action'\]\), 'Unknown action', selectedEntry\.metadata\)/);
  });

  it('exports the filtered events with their hashes and states what the page does not verify', () => {
    assert.match(governance, /return `\/v1\/audit-log\/export\$\{query \? `\?\$\{query\}` : ''\}`;/);
    assert.match(governance, /`audit-log-\$\{filters\.since \|\| 'start'\}-\$\{filters\.until \|\| 'now'\}-\$\{digest8\}\.json`/);
    assert.match(auditPage, /downloadJsonFile\(auditExportFilename\(applied, digest\), payload\)/);
    assert.match(auditPage, />\s*Export filtered events\s*</);
    assert.match(auditPage, /No events match the applied filters, so there is nothing to export\./);
    assert.match(auditPage, /Entries are append-only and hash-chained\. Each export includes every entry's hash and previous hash so the chain can be checked offline\./);
  });
});

describe('address state uses the shared allowlisted route parameters', () => {
  it('never writes the hash directly, so unknown or credential-like parameters are dropped', () => {
    for (const source of [pageComponents, governance, schedules, library]) {
      assert.doesNotMatch(source, /window\.history\.replaceState\(/);
    }
    assert.match(schedules, /replaceRouteParams\(\{ status: next === 'all' \? null : next \}\)/);
    assert.match(settingsPage, /replaceRouteParams\(\{ tab: next === 'organization' \? null : next \}\)/);
    assert.match(checkDetail, /&target=\$\{encodeURIComponent\(callerTargetId\)\}/);
  });

  it('resolves an incoming audit event outside the loaded page by exact read only', () => {
    assert.match(auditPage, /\/v1\/audit-log\/\$\{encodeURIComponent\(selectedId\)\}/);
    assert.match(auditPage, /getString\(entry, \['id'\], ''\) === selectedId/);
    assert.match(auditPage, /Loaded by exact ID; it is not on the current page of results\./);
  });
});
