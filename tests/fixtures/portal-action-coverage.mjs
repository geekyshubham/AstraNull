import { ROLES, PERMISSIONS } from '../../src/contracts/roles.mjs';
import { STAFF_ROLES } from '../../src/contracts/staffRoles.mjs';

export const CUSTOMER_ACTION_ROLES = Object.freeze([...ROLES]);
export const STAFF_ACTION_ROLES = Object.freeze([...STAFF_ROLES]);
export const ACTION_STATES = Object.freeze(['success', 'busy', 'empty', 'invalid', 'cancel', 'error-retry', 'denial', 'reload']);
export const ACTION_DATASETS = Object.freeze(['baseline', 'empty', 'edge']);

/** These are explicit backend gates, not route authorization or dataset-read permissions. */
export const MUTATING_ACTION_FAMILIES = Object.freeze([
  { id: 'scan.create', method: 'POST', path: '/v1/validation-scans', permission: 'test_run:start', body: { target_ids: ['tgt_1'], check_ids: ['origin.leak_scan.safe'] } },
  { id: 'scan.edit', method: 'PATCH', path: '/v1/validation-scans/scan_missing', permission: 'test_run:start', body: { name: 'denied-edit' } },
  { id: 'scan.cancel', method: 'POST', path: '/v1/validation-scans/scan_missing/cancel', permission: 'test_run:start', body: { reason: 'denied-stop' } },
  { id: 'target.create', method: 'POST', path: '/v1/targets', permission: 'target_group:write', body: { kind: 'fqdn', value: 'denied.example.test' } },
  { id: 'target.csv-import', method: 'POST', path: '/v1/targets:csv', permission: 'target_group:write', body: {} },
  { id: 'target.edit', method: 'PATCH', path: '/v1/targets/tgt_missing', permission: 'target_group:write', body: { tags: ['env:denied'] } },
  { id: 'target.remove', method: 'DELETE', path: '/v1/targets/tgt_missing', permission: 'target_group:write', body: {} },
  { id: 'target.authorization', method: 'POST', path: '/v1/targets/tgt_missing/authorization', permission: 'target_group:write', body: { signer_name: 'Synthetic denied signer', signer_email: 'denied@example.test' } },
  { id: 'target.dns-issue', method: 'POST', path: '/v1/targets/tgt_missing/dns-ownership/issue', permission: 'target_group:write', body: {} },
  { id: 'target.dns-verify', method: 'POST', path: '/v1/targets/tgt_missing/dns-ownership/verify', permission: 'target_group:write', body: { challenge_id: 'dns_missing' } },
  { id: 'custody.verify', method: 'POST', path: '/v1/custody/verify', permission: 'evidence:read', body: { payload: {}, custody: {} } },
  { id: 'connector.create', method: 'POST', path: '/v1/connectors', permission: 'waf:connector_write', body: { provider: 'cloudflare', name: 'denied-connector', config: { read_only: true } } },
  { id: 'connector.validate', method: 'POST', path: '/v1/connectors/con_missing/validate', permission: 'waf:connector_write', body: {} },
  { id: 'connector.disable', method: 'POST', path: '/v1/connectors/con_missing/disable', permission: 'waf:connector_write', body: {} },
  { id: 'vault.create', method: 'POST', path: '/v1/secrets', permission: 'secret:write', body: { purpose: 'connector', name: 'denied-secret', plaintext: 'synthetic-never-a-provider-credential' } },
  { id: 'vault.rotate', method: 'POST', path: '/v1/secrets/secret_missing/rotate', permission: 'secret:rotate', body: { plaintext: 'synthetic-never-a-provider-credential' } },
  { id: 'service-account.create', method: 'POST', path: '/v1/service-accounts', permission: 'service_account:create', body: { name: 'denied-account', role: 'viewer', scopes: ['report:read'] } },
  { id: 'service-account.rotate', method: 'POST', path: '/v1/service-accounts/sacc_missing/rotate', permission: 'service_account:rotate', body: {} },
  { id: 'service-account.revoke', method: 'POST', path: '/v1/service-accounts/sacc_missing/revoke', permission: 'service_account:revoke', body: {} },
  { id: 'report.create', method: 'POST', path: '/v1/reports', permission: 'report:create', body: { kind: 'technical', scope: {} } },
  { id: 'finding.triage', method: 'PATCH', path: '/v1/findings/fnd_missing', permission: 'finding:write', body: { status: 'in_progress' } },
  { id: 'notifications.create', method: 'POST', path: '/v1/notifications', permission: 'notification:write', body: { name: 'denied-rule', event: 'finding.created', channel: 'in_app', enabled: true } },
  { id: 'notifications.edit', method: 'PATCH', path: '/v1/notifications/ntf_missing', permission: 'notification:write', body: { enabled: false } },
  { id: 'notifications.remove', method: 'DELETE', path: '/v1/notifications/ntf_missing', permission: 'notification:write', body: {} },
  { id: 'notifications.retry', method: 'POST', path: '/v1/notifications/retries/process', permission: 'notification:write', body: {} },
  { id: 'notifications.redrive', method: 'POST', path: '/v1/notifications/dlq/redrive', permission: 'notification:write', body: {} },
  { id: 'settings.organization', method: 'PATCH', path: '/v1/tenants/current', permission: 'tenant:write', body: { name: 'denied-organization' } },
]);

export const STAFF_MUTATING_ACTION_FAMILIES = Object.freeze([
  { id: 'staff.signup.approve', method: 'POST', path: '/internal/admin/signup-requests/signup_missing/approve', permission: 'staff:signup:decide', body: { note: 'Synthetic denied approval' } },
  { id: 'staff.signup.reject', method: 'POST', path: '/internal/admin/signup-requests/signup_missing/reject', permission: 'staff:signup:decide', body: { note: 'Synthetic denied rejection' } },
  { id: 'staff.tenant.edit', method: 'PATCH', path: '/internal/admin/tenants/ten_demo', permission: 'staff:tenant:write', body: { name: 'denied-tenant' } },
  { id: 'staff.subscription.edit', method: 'PATCH', path: '/internal/admin/tenants/ten_demo/subscription', permission: 'staff:subscription:write', body: { status: 'active' } },
  { id: 'staff.entitlement.edit', method: 'POST', path: '/internal/admin/tenants/ten_demo/entitlements', permission: 'staff:entitlement:write', body: { entitlement_key: 'denied', enabled: true } },
]);

export const DELEGATING_OWNERS = Object.freeze(new Set(['Button', 'AnchorButton', 'Select', 'EmptyState', 'EmptyStateAction', 'TabButton', 'Tabs', 'ShellIconButton', 'NavLink', 'FormModal', 'ConfirmModal', 'ConfirmModalProvider', 'Toast', 'DataTableBodyRow', 'VariantSwitch']));

function delegatedCallbacks(action) {
  const unresolved = action.traits?.unresolvedCallbacks ?? [];
  const bindings = action.traits?.callerBindings ?? {};
  const supplying = (name) => bindings[name].callers - (bindings[name].omitted ?? 0);
  const bound = unresolved.every((name) => bindings[name] && supplying(name) > 0 && bindings[name].resolved === supplying(name));
  return DELEGATING_OWNERS.has(action.owner) && unresolved.length && bound ? unresolved : [];
}

/** AST-derived transaction states. Unknown callback behavior is a blocking classification gap, never an N/A. */
export function actionStateApplicability(action) {
  const traits = action.traits ?? {};
  const requests = traits.requests ?? [];
  const local = ['field', 'select', 'checkable', 'disclosure'].includes(action.kind) && !requests.length;
  const anchor = action.kind === 'anchor' || traits.navigation;
  const mutation = requests.some((request) => ['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method));
  const result = Object.fromEntries(ACTION_STATES.map((state) => [state, { applicable: false, reason: `The resolved callback for this ${action.kind} owns no ${state} transition; caller transactions and route/data denials have separate obligations.` }]));
  result.success = { applicable: true, reason: 'Exact semantic activation/value/URL/panel/request outcome is required.' };
  if (traits.emptySurface || action.context === 'empty-cta') result.empty = { applicable: true, reason: 'Source contains an explicit empty dataset branch/CTA; assert its activation, not merely its presence.' };
  if (traits.permissions?.length || traits.authorizationGuards?.length) result.denial = { applicable: true, reason: `Source action permission guards: ${traits.permissions?.join(', ') || 'explicit source role predicate'}. Route and dataset authorization remain separate dimensions.` };
  if (local && !traits.unresolvedCallbacks?.length) {
    if (traits.validation) result.invalid = { applicable: true, reason: 'This local field owns a source-declared required/bounds/format validation constraint.' };
    return result;
  }
  if (anchor) result.reload = { applicable: true, reason: 'Exact link destination must survive direct load/reload.' };
  if (traits.busy && requests.length) result.busy = { applicable: true, reason: 'Resolved request callback and explicit busy/disabled/loading source state require duplicate-prevention assertions.' };
  if (requests.length || traits.clipboard) result['error-retry'] = { applicable: true, reason: 'Resolved network/clipboard boundary can fail; assert visible failure and explicit retry without duplicate successful side effects.' };
  if (action.kind === 'form-keyboard' && traits.validation) result.invalid = { applicable: true, reason: 'This submitting form has native or callback-owned validation; invalid keyboard submission must issue zero writes.' };
  if (traits.confirmation || traits.modalBoundary || action.handlers?.onCancel || /^(Cancel|Discard|Close|Change choices)(?:\s|$)/.test(action.label) || /(?:event\.key|key)\s*===\s*['"]Escape['"]/.test(action.handlers?.onKeyDown ?? '')) result.cancel = { applicable: true, reason: 'Source owns an explicit review/confirmation/cancel boundary; assert zero writes and applicable retained/cleared draft.' };
  if (mutation) result.reload = { applicable: true, reason: 'Resolved POST/PATCH/PUT/DELETE transaction owns persisted business state; reload must preserve the accepted result without replay.' };
  const delegated = delegatedCallbacks(action);
  if (delegated.length && action.kind !== 'anchor') {
    const callers = Math.max(...delegated.map((name) => traits.callerBindings[name].callers));
    const omitted = Math.max(...delegated.map((name) => traits.callerBindings[name].omitted ?? 0));
    const omission = omitted ? `; ${omitted} omit it, which leaves no handler` : '';
    for (const state of ['busy', 'invalid', 'cancel', 'error-retry', 'denial', 'reload']) if (!result[state].applicable) result[state] = { applicable: false, reason: `Shared primitive forwarding ${delegated.join(', ')}: all ${callers - omitted} supplying mounted callers bind a resolved callback${omission}, and each caller is its own inventoried semantic action that owns the ${state} transition; this primitive owns native activation only.` };
  } else if (traits.unresolvedCallbacks?.length && action.kind !== 'anchor') {
    for (const state of ['busy', 'invalid', 'cancel', 'error-retry', 'denial', 'reload']) if (!result[state].applicable) result[state] = { applicable: null, reason: `Unresolved injected callback ${traits.unresolvedCallbacks.join(', ')}: explicit semantic caller binding still required; this is not N/A.` };
  }
  return result;
}

export function deniedCustomerRoles(permission) {
  if (!PERMISSIONS[permission]) throw new Error(`Unknown action permission ${permission}`);
  return CUSTOMER_ACTION_ROLES.filter((role) => !PERMISSIONS[permission].includes(role));
}
