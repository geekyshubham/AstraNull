import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { requireStaffPermission } from '../../src/lib/staffRbac.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

describe('staff RBAC denial auditing', () => {
  it('allows a staff role that holds the permission without auditing a denial', () => {
    freshStore();
    const gate = requireStaffPermission(
      { staffId: 'staff_admin', staffRole: 'internal_admin' },
      'staff:signup:read',
    );
    assert.equal(gate.ok, true);
    assert.equal((getStore().internalAuditLog ?? []).length, 0);
  });

  it('denies soc_lead for staff:signup:read and audits via dev auditInternal in dev mode', () => {
    freshStore();
    const gate = requireStaffPermission(
      { staffId: 'staff_soc', staffRole: 'soc_lead' },
      'staff:signup:read',
    );
    assert.equal(gate.ok, false);
    assert.equal(gate.status, 403);
    assert.equal(gate.body.error, 'forbidden');
    assert.equal(gate.body.permission, 'staff:signup:read');
    const denied = (getStore().internalAuditLog ?? []).find((a) => a.action === 'staff.rbac.denied');
    assert.ok(denied, 'dev-mode denial should be written to the internal audit log');
    assert.equal(denied.staff_role, 'soc_lead');
    assert.equal(denied.metadata.permission, 'staff:signup:read');
  });

  it('in Postgres mode appends the denial through the injected service, never the dev store', async () => {
    freshStore();
    const calls = [];
    const gate = requireStaffPermission(
      {
        staffId: 'staff_soc',
        staffRole: 'soc_lead',
        persistenceMode: 'postgres',
        internalAuditService: {
          async appendInternalAudit(ctx, event) {
            calls.push({ ctx, event });
          },
        },
      },
      'staff:signup:read',
    );
    // Response is immediate even though the audit append is async/best-effort.
    assert.equal(gate.ok, false);
    assert.equal(gate.status, 403);
    assert.equal(gate.body.permission, 'staff:signup:read');
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].event.action, 'staff.rbac.denied');
    assert.equal(calls[0].event.metadata.permission, 'staff:signup:read');
    // Dev store must stay untouched under Postgres mode.
    assert.equal((getStore().internalAuditLog ?? []).length, 0);
  });

  it('never turns a denial into an error when the injected audit append rejects', async () => {
    freshStore();
    const gate = requireStaffPermission(
      {
        staffId: 'staff_soc',
        staffRole: 'soc_lead',
        persistenceMode: 'postgres',
        internalAuditService: {
          async appendInternalAudit() {
            throw new Error('audit backend down');
          },
        },
      },
      'staff:signup:read',
    );
    assert.equal(gate.ok, false);
    assert.equal(gate.status, 403);
    // Let the rejected promise settle; .catch(() => {}) must swallow it.
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal((getStore().internalAuditLog ?? []).length, 0);
  });
});
