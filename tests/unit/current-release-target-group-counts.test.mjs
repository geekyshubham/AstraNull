import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  listTargetGroups,
  listTargetGroupsEnvelope,
} from '../../src/services/targetGroups.mjs';
import { listFindingsEnvelope } from '../../src/services/findings.mjs';
import { findingMatchesListQuery } from '../../src/lib/findingList.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };
const FOREIGN_TENANT = 'ten_foreign';

function pushFinding(overrides = {}) {
  const record = {
    id: overrides.id ?? `fnd_${getStore().findings.length + 1}`,
    tenant_id: overrides.tenant_id ?? ctx.tenantId,
    target_group_id: overrides.target_group_id ?? null,
    target_id: overrides.target_id ?? null,
    check_id: overrides.check_id ?? 'chk_x',
    title: overrides.title ?? 'Gap',
    severity: overrides.severity ?? 'medium',
    status: overrides.status,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  for (const key of Object.keys(record)) {
    if (record[key] === undefined) delete record[key];
  }
  if (overrides.state !== undefined) record.state = overrides.state;
  if (overrides.deleted_at !== undefined) record.deleted_at = overrides.deleted_at;
  getStore().findings.push(record);
  return record;
}

/** Member target ids per group, mirroring the findings-list membership helper. */
function groupMemberIds(groupId) {
  const ids = new Set();
  for (const target of getStore().targets) {
    if (target.tenant_id !== ctx.tenantId || target.deleted_at) continue;
    if (target.target_group_id === groupId) ids.add(target.id);
  }
  return ids;
}

/** Findings-list decision for one group, the contract the counter must agree with. */
function findingsListMatches(finding, groupId) {
  return finding.tenant_id === ctx.tenantId
    && findingMatchesListQuery(finding, { target_group_id: groupId }, groupMemberIds(groupId));
}

function countsByGroupId(items) {
  return new Map(items.map((group) => [group.id, group.open_findings_count]));
}

describe('current-release target group open findings counts', () => {
  beforeEach(() => {
    freshStore();
    const store = getStore();
    // Self-contained fixture: the shared reset preloads tenant tg_1, tgt_1, and a
    // signed LOA for tg_1. Clear the group/target/LOA arrays so every count below
    // is exact for the rows this test declares.
    store.targetGroups = [];
    store.targets = [];
    store.loaSignatures = [];
    store.targetGroups.push(
      { id: 'tg_count', tenant_id: ctx.tenantId, name: 'Counted', created_at: '2026-09-01T00:00:00.000Z' },
      { id: 'tg_bare', tenant_id: ctx.tenantId, name: 'Bare', created_at: '2026-09-02T00:00:00.000Z' },
      { id: 'tg_archived', tenant_id: ctx.tenantId, name: 'Archived', archived_at: '2026-09-03T00:00:00.000Z' },
    );
    store.targets.push(
      { id: 'tgt_count', tenant_id: ctx.tenantId, target_group_id: 'tg_count', kind: 'fqdn', value: 'a.example' },
      { id: 'tgt_moved', tenant_id: ctx.tenantId, target_group_id: 'tg_bare', kind: 'fqdn', value: 'b.example' },
      { id: 'tgt_dead', tenant_id: ctx.tenantId, target_group_id: 'tg_count', kind: 'fqdn', value: 'dead.example', deleted_at: '2026-09-04T00:00:00.000Z' },
    );
    store.loaSignatures.push({
      id: 'loa_count',
      tenant_id: ctx.tenantId,
      target_group_id: 'tg_count',
      state: 'signed',
      signer_name: 'Counted Signer',
      signed_at: '2026-09-05T00:00:00.000Z',
    });
    store.tenants.push({ id: FOREIGN_TENANT, name: 'Foreign' });
  });

  it('counts beyond the 50-finding findings page cap with the whole-tenant match set', () => {
    for (let i = 0; i < 55; i += 1) {
      pushFinding({ id: `fnd_bulk_${i}`, target_group_id: 'tg_count', target_id: 'tgt_count' });
    }
    // A page-sized projection must not equal the authoritative count.
    assert.equal(findingsListMatches(getStore().findings[0], 'tg_count'), true);

    const groups = listTargetGroups(ctx);
    assert.equal(countsByGroupId(groups).get('tg_count'), 55);
  });

  it('matches the shared findings-list predicate for moved and inconsistent membership', () => {
    // Stored in tg_count, but the target was moved to tg_bare: the shared predicate
    // (stored group OR active member target) matches both groups.
    const moved = pushFinding({ id: 'fnd_moved', target_group_id: 'tg_count', target_id: 'tgt_moved' });
    const storedOnly = pushFinding({ id: 'fnd_stored_only', target_group_id: 'tg_bare', target_id: null });
    const memberOnly = pushFinding({ id: 'fnd_member_only', target_id: 'tgt_count', target_group_id: null });

    const counts = countsByGroupId(listTargetGroups(ctx));
    // Each matching group counts the moved finding exactly once: no duplicate
    // count within a group. The shared predicate can match a finding to two
    // groups (stored group plus moved member target), so the sum across groups
    // is not a unique tenant total — per-group counts and per-finding links
    // stay authoritative.
    assert.equal(counts.get('tg_count'), 2);
    assert.equal(counts.get('tg_bare'), 2);
    for (const finding of [moved, storedOnly, memberOnly]) {
      for (const groupId of ['tg_count', 'tg_bare']) {
        assert.equal(
          findingsListMatches(finding, groupId),
          ['fnd_moved'].includes(finding.id) || (finding.id === 'fnd_stored_only' && groupId === 'tg_bare')
            || (finding.id === 'fnd_member_only' && groupId === 'tg_count'),
          `${finding.id} vs ${groupId}`,
        );
      }
    }
  });

  it('counts the exact open state only and excludes in_progress with closures', () => {
    pushFinding({ id: 'fnd_open', target_group_id: 'tg_count', status: 'open' });
    pushFinding({ id: 'fnd_progress', target_group_id: 'tg_count', status: 'in_progress' });
    pushFinding({ id: 'fnd_remediation', target_group_id: 'tg_count', status: 'remediation_pending' });
    pushFinding({ id: 'fnd_accepted', target_group_id: 'tg_count', status: 'accepted_risk' });
    pushFinding({ id: 'fnd_resolved', target_group_id: 'tg_count', status: 'resolved' });
    pushFinding({ id: 'fnd_closed', target_group_id: 'tg_count', status: 'closed' });
    pushFinding({ id: 'fnd_false_positive', target_group_id: 'tg_count', status: 'false_positive' });
    pushFinding({ id: 'fnd_accepted_plain', target_group_id: 'tg_count', status: 'accepted' });

    // Open means exactly `open` (the isFindingOpen contract behind the
    // `status=open` link): in_progress is the UI Active bucket, and every
    // closure status is excluded.
    const counts = countsByGroupId(listTargetGroups(ctx)).get('tg_count');
    assert.equal(counts, 1);
    assert.equal(listFindingsEnvelope(ctx, { target_group_id: 'tg_count', status: 'open' }).total, counts);
  });

  it('keeps missing lifecycle data and the legacy state field in the open set', () => {
    pushFinding({ id: 'fnd_missing_status', target_group_id: 'tg_count', status: undefined });
    pushFinding({ id: 'fnd_legacy_state', target_group_id: 'tg_count', status: undefined, state: 'open' });
    pushFinding({ id: 'fnd_state_accepted', target_group_id: 'tg_count', status: undefined, state: 'accepted' });

    const counts = countsByGroupId(listTargetGroups(ctx));
    assert.equal(counts.get('tg_count'), 2);
  });

  it('never counts another tenant, even with the same ids', () => {
    pushFinding({ id: 'fnd_foreign', tenant_id: FOREIGN_TENANT, target_group_id: 'tg_count', target_id: 'tgt_count' });
    pushFinding({ id: 'fnd_foreign_member', tenant_id: FOREIGN_TENANT, target_id: 'tgt_count' });

    const counts = countsByGroupId(listTargetGroups(ctx));
    assert.equal(counts.get('tg_count'), 0);
    assert.equal(counts.get('tg_bare'), 0);
  });

  it('returns a real zero for a group with no matching findings, and skips deleted membership', () => {
    pushFinding({ id: 'fnd_dead_target', target_group_id: null, target_id: 'tgt_dead' });

    const groups = listTargetGroups(ctx);
    const counts = countsByGroupId(groups);
    assert.equal(counts.has('tg_bare'), true);
    assert.equal(counts.get('tg_bare'), 0);
    // A deleted target does not extend membership.
    assert.equal(counts.get('tg_count'), 0);
    for (const group of groups) {
      assert.equal(typeof group.open_findings_count, 'number');
      assert.equal(Number.isInteger(group.open_findings_count), true);
    }
  });

  it('keeps the existing list shape additive and the envelope contract intact', () => {
    pushFinding({ id: 'fnd_shape', target_group_id: 'tg_count', target_id: 'tgt_count' });

    const envelope = listTargetGroupsEnvelope(ctx);
    assert.equal(envelope.count, 2);
    assert.equal(envelope.meta.empty_reason, null);
    const group = envelope.items.find((item) => item.id === 'tg_count');
    assert.equal(group.target_count, 1);
    assert.equal(group.loa_state, 'signed');
    assert.equal(group.name, 'Counted');
    assert.equal(group.open_findings_count, 1);
    // Archived rows stay out of the active list but keep their count on the archived view.
    assert.equal(listTargetGroups(ctx, { archived: true }).map((g) => g.open_findings_count).length, 1);
  });
});
