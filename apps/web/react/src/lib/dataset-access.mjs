import { roleHasPermission } from '../../../../../src/contracts/roles.mjs';
import { staffRoleHasPermission } from '../../../../../src/contracts/staffRoles.mjs';

/** Read permission enforced by the backend list endpoint behind each role-restricted customer dataset. */
export const CUSTOMER_DATASET_PERMISSIONS = Object.freeze({
  audit: 'audit:read',
  releaseEvidence: 'release_evidence:read',
  releaseAttestation: 'release_evidence:read',
  notifications: 'notification:read',
  connectors: 'waf:connector_read',
  secrets: 'secret:read',
  serviceAccounts: 'service_account:read',
});

/** Read permission enforced by each `/internal/admin/*` list endpoint. */
export const STAFF_DATASET_PERMISSIONS = Object.freeze({
  internalOverview: 'staff:signup:read',
  internalSignupRequests: 'staff:signup:read',
  internalTenants: 'staff:tenant:read',
  internalApprovalRequests: 'staff:approval:read',
  internalAudit: 'staff:audit:read',
});

const STAFF_SOC_IMPERSONATION_ROLE = 'soc';

function normalize(value) {
  return String(value ?? '').trim().toLowerCase();
}

/**
 * @param {{ principal?: string; role?: string; staff_role?: string } | null | undefined} session
 * @param {string} dataset
 */
export function canReadDataset(session, dataset) {
  const isStaff = normalize(session?.principal) === 'staff';
  const staffPermission = STAFF_DATASET_PERMISSIONS[dataset];
  if (staffPermission) return staffSessionHasPermission(session, staffPermission);
  const permission = CUSTOMER_DATASET_PERMISSIONS[dataset];
  if (!permission) return true;
  const role = isStaff ? STAFF_SOC_IMPERSONATION_ROLE : normalize(session?.role);
  if (!role) return true;
  return roleHasPermission(role, permission);
}

/**
 * Customer-principal permission check for write affordances; unknown roles defer to the backend.
 * @param {{ principal?: string; role?: string } | null | undefined} session
 * @param {string} permission
 */
export function sessionHasPermission(session, permission) {
  if (normalize(session?.principal) === 'staff') return false;
  const role = normalize(session?.role);
  if (!role) return true;
  return roleHasPermission(role, permission);
}

/**
 * @param {{ principal?: string; staff_role?: string } | null | undefined} session
 * @param {string} permission
 */
export function staffSessionHasPermission(session, permission) {
  return normalize(session?.principal) === 'staff' && staffRoleHasPermission(normalize(session?.staff_role), permission);
}
