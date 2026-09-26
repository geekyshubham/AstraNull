import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { PERMISSIONS, ROLES, roleHasPermission } from '../../src/contracts/roles.mjs';
import { STAFF_PERMISSIONS, STAFF_ROLES } from '../../src/contracts/staffRoles.mjs';
import {
  canReadDataset,
  CUSTOMER_DATASET_PERMISSIONS,
  sessionHasPermission,
  STAFF_DATASET_PERMISSIONS,
  staffSessionHasPermission,
} from '../../apps/web/react/src/lib/dataset-access.mjs';
import { staffHomePath, staffHomeRoute } from '../../apps/web/react/src/lib/portal-auth-policy.mjs';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.mjs';
import { PORTAL_ROUTE_DATASETS } from '../../apps/web/react/src/lib/types.ts';

const ROOT = new URL('../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');

function readableRouteDatasets(session, route) {
  return PORTAL_ROUTE_DATASETS[route].filter((dataset) => canReadDataset(session, dataset));
}

function loaderPath(apiSource, dataset) {
  const match = apiSource.match(new RegExp(`\\n\\s+${dataset}: \\(\\) => [^\\n]*?'(/[^'?]+)`));
  assert.ok(match, `no loader path found for ${dataset}`);
  return match[1];
}

describe('portal dataset access policy', () => {
  it('maps every gated dataset to a real backend permission', () => {
    for (const [dataset, permission] of Object.entries(CUSTOMER_DATASET_PERMISSIONS)) {
      assert.ok(PERMISSIONS[permission], `${dataset} → ${permission} is not a customer permission`);
    }
    for (const [dataset, permission] of Object.entries(STAFF_DATASET_PERMISSIONS)) {
      assert.ok(STAFF_PERMISSIONS[permission], `${dataset} → ${permission} is not a staff permission`);
    }
  });

  it('gates each dataset with the permission its backend list endpoint enforces', () => {
    const apiSource = read('apps/web/react/src/lib/api.ts');
    const serverSource = read('src/server.mjs');
    const gates = { ...CUSTOMER_DATASET_PERMISSIONS, ...STAFF_DATASET_PERMISSIONS };
    for (const [dataset, permission] of Object.entries(gates)) {
      const path = loaderPath(apiSource, dataset);
      const handler = serverSource.match(
        new RegExp(`(?:method === 'GET' && path === '${path}'|path === '${path}' && method === 'GET'\\) \\{)[\\s\\S]{0,120}?require(?:Staff)?Permission\\(ctx, '([^']+)'`)
      );
      assert.ok(handler, `no GET handler gate found for ${path}`);
      assert.equal(handler[1], permission, `${dataset} (${path})`);
    }
  });

  it('matches roles.mjs for every customer role', () => {
    for (const role of ROLES) {
      for (const [dataset, permission] of Object.entries(CUSTOMER_DATASET_PERMISSIONS)) {
        assert.equal(canReadDataset({ role }, dataset), roleHasPermission(role, permission), `${role} ${dataset}`);
      }
      assert.equal(canReadDataset({ role }, 'targetGroups'), true);
    }
  });

  it('never requests an unreadable dataset on a route the customer role may open', () => {
    for (const role of ROLES) {
      for (const route of Object.keys(PORTAL_ROUTE_DATASETS)) {
        if (!canAccessRoute(role, route)) continue;
        for (const dataset of readableRouteDatasets({ role }, route)) {
          const permission = CUSTOMER_DATASET_PERMISSIONS[dataset];
          if (permission) assert.ok(roleHasPermission(role, permission), `${role} ${route} ${dataset}`);
        }
      }
    }
  });

  it('drops the audited 403 offenders for restricted customer roles', () => {
    assert.deepEqual(readableRouteDatasets({ role: 'viewer' }, 'reports'), ['reports']);
    assert.deepEqual(readableRouteDatasets({ role: 'engineer' }, 'reports'), ['reports']);
    assert.ok(readableRouteDatasets({ role: 'auditor' }, 'reports').includes('audit'));
    assert.ok(!readableRouteDatasets({ role: 'viewer' }, 'agent-detail').includes('audit'));
    assert.ok(!PORTAL_ROUTE_DATASETS.agents.includes('releaseEvidence'));
    assert.deepEqual(readableRouteDatasets({ role: 'soc' }, 'integrations'), ['targetGroups']);
    assert.deepEqual(readableRouteDatasets({ role: 'engineer' }, 'integrations'), ['connectors', 'targetGroups']);
    assert.deepEqual(readableRouteDatasets({ role: 'engineer' }, 'settings'), ['targetGroups', 'agents', 'evidence', 'bootstrapTokens']);
    assert.deepEqual(readableRouteDatasets({ role: 'viewer' }, 'settings'), ['targetGroups', 'agents', 'evidence']);
    assert.deepEqual(readableRouteDatasets({ role: 'auditor' }, 'settings'), PORTAL_ROUTE_DATASETS.settings);
    assert.ok(!readableRouteDatasets({ role: 'viewer' }, 'target-group-detail').includes('connectors'));
    assert.ok(!readableRouteDatasets({ role: 'soc' }, 'target-group-detail').includes('connectors'));
  });

  it('defers to the backend when the customer role is unknown', () => {
    assert.equal(canReadDataset({}, 'audit'), true);
    assert.equal(sessionHasPermission({}, 'secret:write'), true);
  });

  it('scopes the admin console datasets to each staff role', () => {
    const adminFor = (staffRole) => readableRouteDatasets({ principal: 'staff', staff_role: staffRole }, 'admin');
    assert.deepEqual(adminFor('internal_admin'), PORTAL_ROUTE_DATASETS.admin);
    assert.deepEqual(adminFor('security_admin'), PORTAL_ROUTE_DATASETS.admin);
    assert.deepEqual(adminFor('support_engineer'), ['internalOverview', 'internalSignupRequests', 'internalTenants', 'internalApprovalRequests']);
    assert.deepEqual(adminFor('billing_ops'), ['internalTenants', 'internalApprovalRequests']);
    assert.deepEqual(adminFor('soc_analyst'), ['internalApprovalRequests']);
    assert.deepEqual(adminFor('soc_lead'), ['internalApprovalRequests']);
    assert.equal(canReadDataset({ role: 'admin' }, 'internalTenants'), false);
  });

  it('checks staff write affordances against staffRoles.mjs', () => {
    for (const staffRole of STAFF_ROLES) {
      for (const [permission, roles] of Object.entries(STAFF_PERMISSIONS)) {
        assert.equal(staffSessionHasPermission({ principal: 'staff', staff_role: staffRole }, permission), roles.includes(staffRole));
      }
    }
    assert.equal(staffSessionHasPermission({ role: 'admin' }, 'staff:tenant:write'), false);
    assert.equal(sessionHasPermission({ principal: 'staff', staff_role: 'internal_admin' }, 'secret:write'), false);
  });
});

describe('staff home routing', () => {
  it('sends operational SOC staff to the SOC console and everyone else to internal admin', () => {
    for (const staffRole of STAFF_ROLES) {
      const soc = staffRole === 'soc_analyst' || staffRole === 'soc_lead';
      assert.equal(staffHomePath({ principal: 'staff', staff_role: staffRole }), soc ? '/internal/soc' : '/internal/admin');
      assert.equal(staffHomeRoute({ principal: 'staff', staff_role: staffRole }), soc ? 'internal-soc' : 'admin');
      assert.equal(canAccessRoute(undefined, staffHomeRoute({ staff_role: staffRole }), { principal: 'staff', staffRole }), true);
    }
  });

  it('does not hard-code the admin console as the post-sign-in destination', () => {
    const publicPages = read('apps/web/react/src/pages/public-pages.tsx');
    assert.equal(/location\.(?:href\s*=|replace\()\s*\(?'\/internal\/admin'/.test(publicPages), false);
    assert.match(publicPages, /staffHomePath\(/);
    const app = read('apps/web/react/src/App.tsx');
    assert.match(app, /staffHomeRoute\(/);
    assert.match(app, /setAccessNotice\(routeDeniedNotice\(/);
  });
});
