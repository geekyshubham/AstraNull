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
const subscriptionPage = between(pageComponents, 'export function SubscriptionPage(', 'export function StaffSurfacePage(');
const targetGroupsPage = between(pageComponents, 'export function TargetGroupsPage(', 'type ReportExportFormat');
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

describe('target groups', () => {
  it('leads with the group name and states undeclared owner and criticality', () => {
    assert.match(targetGroupsPage, /className="tg-name-link"/);
    assert.match(targetGroupsPage, /Owner not declared/);
    assert.match(targetGroupsPage, /Criticality not declared/);
  });

  it('does not preselect the first group for Add target and does not treat zero findings as healthy', () => {
    assert.match(targetGroupsPage, /const \[addTargetGroupId, setAddTargetGroupId\] = useState\(''\);/);
    assert.doesNotMatch(targetGroupsPage, /<Badge tone="success">0<\/Badge>/);
    assert.match(targetGroupsPage, /None checked/);
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
    assert.match(generate, /if \(scopeMode === 'groups'\) body\.target_group_ids = \[\.\.\.selectedGroupIds\];/);
    assert.match(generate, /if \(scopeMode === 'targets'\) body\.target_ids = \[\.\.\.selectedTargetIds\];/);
    assert.doesNotMatch(generate, /body\.(target_id|target_group_id|group_id|scope)\b/);
    assert.match(generate, /describeReportScopeError\(result\)/);
  });

  it('offers scoped modes and limits only as advertised by the report capabilities', () => {
    assert.match(reportsPage, /getNestedItem\(data\.reportCapabilities \?\? \{\}, \['scope'\]\)/);
    assert.match(reportsPage, /scopeFields\.includes\(mode === 'groups' \? 'target_group_ids' : 'target_ids'\)/);
    assert.match(reportsPage, /getOptionalNumber\(scopeCaps, \['max_ids'\]\)/);
    assert.doesNotMatch(pageComponents, /REPORT_SCOPE_LIMIT/);
    assert.match(reportsPage, /was not applied and nothing else was selected in its place/);
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

  it('falls back to the workspace administrator and refuses to copy credential-like notes', () => {
    assert.match(supportPage, /No support channel is configured for this deployment/);
    assert.match(supportPage, /looks like it contains a credential/);
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
    assert.match(notificationsPage, /Rule removed or not recorded/);
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
    assert.match(integrations, /Manual metadata connectors never poll/);
    assert.doesNotMatch(integrations, /Deliveries through it will stop/);
    assert.match(integrations, /label: 'Last successful sync'/);
  });

  it('derives a connector last attempt only from recorded outcomes, never updated_at or poll requests', () => {
    const column = between(integrations, "key: 'last_attempt'", "key: 'actions'");
    assert.match(column, /hasOwnProperty\.call\(item, 'last_error_at'\)\) return <span className="muted">Not recorded<\/span>/);
    assert.match(column, /Date\.parse\(failure\) > Date\.parse\(success\)/);
    assert.match(column, /if \(!connectorHasCredentialPoll\(item\)\) return <span className="muted">Not applicable<\/span>;/);
    assert.doesNotMatch(column, /updated_at|last_poll_requested_at|last_polled_at|last_poll_at/);
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
});

describe('plan and usage', () => {
  it('never renders unknown usage as zero or unlimited and separates access from configuration', () => {
    assert.match(subscriptionPage, /usage not measured \(not zero\)/);
    assert.match(subscriptionPage, /limit not recorded \(not unlimited\)/);
    assert.match(subscriptionPage, /Available does not mean it is configured or working/);
    assert.doesNotMatch(subscriptionPage, /high_scale_requests_per_month/);
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

describe('address state uses the shared allowlisted route parameters', () => {
  it('never writes the hash directly, so unknown or credential-like parameters are dropped', () => {
    for (const source of [pageComponents, governance, schedules, library]) {
      assert.doesNotMatch(source, /window\.history\.replaceState\(/);
    }
    assert.match(schedules, /replaceRouteParams\(\{ status: next === 'all' \? null : next \}\)/);
    assert.match(targetGroupsPage, /replaceRouteParams\(\{ q: query\.trim\(\) \|\| null, view: showArchived \? 'archived' : null \}\)/);
    assert.match(settingsPage, /replaceRouteParams\(\{ tab: next === 'organization' \? null : next \}\)/);
    assert.match(checkDetail, /&group=\$\{encodeURIComponent\(callerGroupId\)\}&target=/);
  });

  it('resolves an incoming audit event outside the loaded page by exact read only', () => {
    assert.match(auditPage, /\/v1\/audit-log\/\$\{encodeURIComponent\(selectedId\)\}/);
    assert.match(auditPage, /getString\(entry, \['id'\], ''\) === selectedId/);
    assert.match(auditPage, /Loaded by exact ID; it is not on the current page of results\./);
  });
});
