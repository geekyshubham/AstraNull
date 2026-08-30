/**
 * Target-detail findings pagination: SQL keyset (seek) pagination.
 *
 * Guards the fix for the unbounded findings read in getTargetDetailBundle. The old
 * implementation selected the FULL per-target findings set and sliced it in Node, so
 * every request scanned every row. These tests assert the read is now bounded by a SQL
 * LIMIT, that the keyset predicate is correctly parameterised, and that walking the
 * cursor yields the same pages as before: same order, no overlap, no gaps.
 *
 * Runs against a real ephemeral Postgres and skips when one is unavailable.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { encodeCursor } from '../../src/lib/cursorPagination.mjs';
import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';

const IDS = Object.freeze({
  tenantId: 'ten_keyset',
  environmentId: 'env_keyset',
  targetGroupId: 'tg_keyset',
  targetId: 'tgt_keyset',
  otherTargetId: 'tgt_keyset_other',
});

const CTX = Object.freeze({ tenantId: IDS.tenantId, userId: 'usr_owner', role: 'owner' });

/**
 * Findings fixture: 24 findings spread over only 6 distinct created_at values, i.e. 4
 * findings share each timestamp. created_at alone is therefore NOT a unique sort key —
 * this is exactly the shape that makes a single-column cursor drop or repeat rows, so
 * it is the shape the (created_at, id) tuple has to survive.
 */
const DISTINCT_TIMESTAMPS = 6;
const FINDINGS_PER_TIMESTAMP = 4;
const TOTAL_FINDINGS = DISTINCT_TIMESTAMPS * FINDINGS_PER_TIMESTAMP;

function buildFindingsFixture() {
  const rows = [];
  for (let t = 0; t < DISTINCT_TIMESTAMPS; t += 1) {
    // Sub-millisecond offsets: TIMESTAMPTZ keeps microseconds but node-postgres parses
    // the column into a millisecond-precision JS Date. If the cursor carried the parsed
    // Date instead of an exact value, these rows would be silently skipped.
    const createdAt = `2026-07-0${t + 1}T12:00:00.123456+00:00`;
    for (let i = 0; i < FINDINGS_PER_TIMESTAMP; i += 1) {
      rows.push({
        id: `fnd_${String(t)}_${String(i)}`,
        created_at: createdAt,
        // Distinct check_id per row: uniq_findings_open_target_check is a partial unique
        // index over (tenant, group, target, check_id) WHERE status = 'open'.
        check_id: `chk_${String(t)}_${String(i)}`,
        status: i % 3 === 0 ? 'open' : i % 3 === 1 ? 'closed' : 'accepted',
        severity: 'high',
      });
    }
  }
  return rows;
}

/**
 * Wrap a pool so every query issued through it is recorded, while still hitting real
 * Postgres. Lets the tests assert on emitted SQL, bound params and returned row counts
 * rather than only on the response body.
 */
function createRecordingPool(pool) {
  const recorded = [];
  return {
    recorded,
    findingsSelects() {
      return recorded.filter(
        (entry) => /FROM findings/i.test(entry.text) && !/COUNT\(\*\)/i.test(entry.text),
      );
    },
    reset() {
      recorded.length = 0;
    },
    async connect() {
      const client = await pool.connect();
      const originalQuery = client.query.bind(client);
      client.query = async (text, params) => {
        const result = await originalQuery(text, params);
        recorded.push({
          text: typeof text === 'string' ? text : String(text?.text ?? ''),
          params: params ?? [],
          rowCount: result?.rows?.length ?? 0,
        });
        return result;
      };
      return client;
    },
  };
}

/**
 * @param {import('pg').Pool} pool
 */
async function seedFindingsFixture(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [IDS.tenantId]);
    await client.query(`INSERT INTO tenants (id, name) VALUES ($1, $2)`, [
      IDS.tenantId,
      'Keyset Tenant',
    ]);
    await client.query(`INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, $3)`, [
      IDS.environmentId,
      IDS.tenantId,
      'keyset env',
    ]);
    await client.query(
      `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ($1, $2, $3, $4)`,
      [IDS.targetGroupId, IDS.tenantId, IDS.environmentId, 'keyset group'],
    );
    for (const targetId of [IDS.targetId, IDS.otherTargetId]) {
      await client.query(
        `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, normalized_value)
         VALUES ($1, $2, $3, 'fqdn', $4, $4)`,
        [targetId, IDS.tenantId, IDS.targetGroupId, `${targetId}.keyset.test`],
      );
    }

    for (const row of buildFindingsFixture()) {
      await client.query(
        `INSERT INTO findings
           (id, tenant_id, target_group_id, target_id, check_id, title, severity, status, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz)`,
        [
          row.id,
          IDS.tenantId,
          IDS.targetGroupId,
          IDS.targetId,
          row.check_id,
          `finding ${row.id}`,
          row.severity,
          row.status,
          row.created_at,
        ],
      );
    }

    // Decoy on a sibling target: must never leak into the paged target's results.
    await client.query(
      `INSERT INTO findings
         (id, tenant_id, target_group_id, target_id, check_id, title, severity, status, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz)`,
      [
        'fnd_other_target',
        IDS.tenantId,
        IDS.targetGroupId,
        IDS.otherTargetId,
        'chk_other',
        'other target finding',
        'high',
        'open',
        '2026-07-03T12:00:00.123456+00:00',
      ],
    );

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Walk every page via the emitted cursor.
 *
 * @param {{ getTargetDetailBundle: Function }} repo
 * @param {number} limit
 */
async function walkAllPages(repo, limit, recordingPool) {
  const pages = [];
  let cursor = undefined;
  // Guard against a cursor that fails to advance: a bounded loop turns an infinite
  // pagination bug into a test failure instead of a hung run.
  for (let guard = 0; guard <= TOTAL_FINDINGS + 5; guard += 1) {
    if (recordingPool) recordingPool.reset();
    const bundle = await repo.getTargetDetailBundle(CTX, IDS.targetId, {
      findings_limit: limit,
      ...(cursor ? { findings_cursor: cursor } : {}),
    });
    assert.ok(bundle, 'expected a target detail bundle');
    pages.push({
      findings: bundle.findings,
      cursor: bundle.findings_next_cursor,
      counts: bundle.counts,
      findingsRowCounts: recordingPool
        ? recordingPool.findingsSelects().map((entry) => entry.rowCount)
        : [],
    });
    if (!bundle.findings_next_cursor) return pages;
    cursor = bundle.findings_next_cursor;
  }
  throw new Error('pagination did not terminate: cursor never went null');
}

const availability = await resolvePostgresHarnessAvailability(process.env);
const describeMaybe = availability.available ? describe : describe.skip;
if (!availability.available) {
  console.log(`target-detail-findings-keyset: skipped — ${availability.reason}`);
}

describeMaybe('target detail findings keyset pagination', () => {
  it('walks all pages with no overlap and no gaps, bounded per request', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const recordingPool = createRecordingPool(pool);
      const repo = createPortalRevampRepository(recordingPool);

      const limit = 5;
      const pages = await walkAllPages(repo, limit, recordingPool);

      const seen = [];
      for (const page of pages) {
        assert.ok(page.findings.length <= limit, 'page exceeded the requested limit');
        for (const finding of page.findings) seen.push(finding.id);
      }

      // No gaps: every seeded finding appears exactly once.
      assert.equal(seen.length, TOTAL_FINDINGS, 'walked page rows should cover every finding');
      // No overlap: ids are unique across the whole walk.
      assert.equal(new Set(seen).size, TOTAL_FINDINGS, 'pages overlapped (duplicate ids)');
      // The sibling target's finding never leaks in.
      assert.ok(!seen.includes('fnd_other_target'), 'tenant/target scoping leaked a row');

      // Ordering is the documented created_at DESC, id DESC and is stable across pages.
      const ordered = [...seen];
      const expected = buildFindingsFixture()
        .slice()
        .sort((a, b) =>
          a.created_at === b.created_at
            ? b.id.localeCompare(a.id)
            : b.created_at.localeCompare(a.created_at),
        )
        .map((row) => row.id);
      assert.deepEqual(ordered, expected, 'walked order must be created_at DESC, id DESC');

      // The SQL read is genuinely bounded: each findings SELECT returns at most
      // limit+1 rows (the +1 being the has-next-page probe), never the full set.
      for (const page of pages) {
        assert.ok(page.findingsRowCounts.length >= 1, 'expected a findings SELECT per request');
        for (const rowCount of page.findingsRowCounts) {
          assert.ok(
            rowCount <= limit + 1,
            `findings SELECT returned ${rowCount} rows; expected <= ${limit + 1}`,
          );
          assert.ok(
            rowCount < TOTAL_FINDINGS,
            'findings SELECT materialized the full set: SQL LIMIT is not applied',
          );
        }
      }
    });
  });

  it('emits a LIMIT and a parameterised (created_at, id) keyset predicate', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const recordingPool = createRecordingPool(pool);
      const repo = createPortalRevampRepository(recordingPool);

      const first = await repo.getTargetDetailBundle(CTX, IDS.targetId, { findings_limit: 5 });
      const firstSelect = recordingPool.findingsSelects()[0];
      assert.ok(firstSelect, 'expected a findings SELECT');
      assert.match(firstSelect.text, /LIMIT \$\d+/, 'findings query must carry a SQL LIMIT');
      assert.match(
        firstSelect.text,
        /ORDER BY created_at DESC, id DESC/,
        'ordering must be the deterministic composite tuple',
      );
      // First page has no cursor, so no seek predicate yet.
      assert.ok(!/\(created_at, id\) </.test(firstSelect.text));
      // limit+1 is bound as a parameter, not interpolated.
      assert.equal(firstSelect.params.at(-1), 6);

      recordingPool.reset();
      await repo.getTargetDetailBundle(CTX, IDS.targetId, {
        findings_limit: 5,
        findings_cursor: first.findings_next_cursor,
      });
      const secondSelect = recordingPool.findingsSelects()[0];
      assert.match(
        secondSelect.text,
        /\(created_at, id\) < \(\$\d+::timestamptz, \$\d+::text\)/,
        'second page must use a row-tuple seek predicate cast to the real column types',
      );
      // Cursor values travel as bound params: tenant, target, created_at, id, limit+1.
      assert.equal(secondSelect.params.length, 5);
      assert.equal(secondSelect.params[0], IDS.tenantId);
      assert.equal(secondSelect.params[1], IDS.targetId);
      assert.equal(secondSelect.params.at(-1), 6);
      assert.equal(typeof secondSelect.params[2], 'string');
      assert.equal(secondSelect.params[3], first.findings.at(-1).id);
    });
  });

  it('clamps a hostile findings_limit server-side', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const recordingPool = createRecordingPool(pool);
      const repo = createPortalRevampRepository(recordingPool);

      await repo.getTargetDetailBundle(CTX, IDS.targetId, { findings_limit: 1_000_000 });
      const select = recordingPool.findingsSelects()[0];
      // Clamped to FINDINGS_PAGE_MAX (100), so the bound limit is 101 regardless of input.
      assert.equal(select.params.at(-1), 101);
    });
  });

  it('preserves the response contract and full-target counts under pagination', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const repo = createPortalRevampRepository(pool);

      const paged = await repo.getTargetDetailBundle(CTX, IDS.targetId, { findings_limit: 3 });
      assert.equal(paged.findings.length, 3);
      assert.deepEqual(Object.keys(paged.findings[0]).sort(), [
        'id',
        'opened_at',
        'owner_group',
        'severity',
        'state',
        'title',
      ]);
      const sample = paged.findings[0];
      assert.equal(typeof sample.opened_at, 'string');
      assert.match(sample.opened_at, /^\d{4}-\d{2}-\d{2}T/);
      assert.ok(['open', 'closed', 'accepted'].includes(sample.state));
      assert.equal(sample.owner_group, 'edge-sre');

      // counts are per-target totals and must NOT shrink to the page size.
      const fixture = buildFindingsFixture();
      const expectedOpen = fixture.filter((row) => row.status === 'open').length;
      const expectedClosed = fixture.filter(
        (row) => row.status === 'closed' || row.status === 'accepted',
      ).length;
      assert.equal(paged.counts.findings_open, expectedOpen);
      assert.equal(paged.counts.findings_closed, expectedClosed);

      // Unpaginated default keeps the documented 20-row cap and emits no cursor.
      const unpaged = await repo.getTargetDetailBundle(CTX, IDS.targetId, {});
      assert.equal(unpaged.findings.length, 20);
      assert.equal(unpaged.findings_next_cursor, null);
      assert.equal(unpaged.counts.findings_open, expectedOpen);
      assert.equal(unpaged.counts.findings_closed, expectedClosed);
    });
  });

  it('accepts a legacy id-only cursor without crashing or restarting the ordering', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const repo = createPortalRevampRepository(pool);

      const page1 = await repo.getTargetDetailBundle(CTX, IDS.targetId, { findings_limit: 5 });
      const boundaryId = page1.findings.at(-1).id;

      // Old-format cursor: only {id}, no created_at. Must resolve to the same next page
      // the keyset cursor produces, not silently hand back page one.
      const legacyCursor = encodeCursor({ id: boundaryId });
      const legacyNext = await repo.getTargetDetailBundle(CTX, IDS.targetId, {
        findings_limit: 5,
        findings_cursor: legacyCursor,
      });
      const keysetNext = await repo.getTargetDetailBundle(CTX, IDS.targetId, {
        findings_limit: 5,
        findings_cursor: page1.findings_next_cursor,
      });

      assert.deepEqual(
        legacyNext.findings.map((f) => f.id),
        keysetNext.findings.map((f) => f.id),
        'legacy cursor must resolve to the same page as the keyset cursor',
      );
      assert.notEqual(legacyNext.findings[0].id, page1.findings[0].id);

      // An unknown / stale id degrades to a documented first page rather than throwing.
      const staleCursor = encodeCursor({ id: 'fnd_does_not_exist' });
      const stale = await repo.getTargetDetailBundle(CTX, IDS.targetId, {
        findings_limit: 5,
        findings_cursor: staleCursor,
      });
      assert.deepEqual(
        stale.findings.map((f) => f.id),
        page1.findings.map((f) => f.id),
        'stale legacy cursor should fall back to the first page',
      );

      // Garbage cursor is ignored rather than fatal.
      const garbage = await repo.getTargetDetailBundle(CTX, IDS.targetId, {
        findings_limit: 5,
        findings_cursor: 'not-a-valid-cursor',
      });
      assert.equal(garbage.findings.length, 5);
    });
  });

  it('keeps verification history ASC and latest-wins semantics under the cap', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const repo = createPortalRevampRepository(pool);

      const states = ['pending', 'dns_verified', 'agent_verified'];
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [IDS.tenantId]);
        for (let i = 0; i < states.length; i += 1) {
          await client.query(
            `INSERT INTO target_verifications
               (id, tenant_id, target_id, state, source_kind, source_ref, transitioned_at, transitioned_by, audit_entry_id)
             VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz,$8,$9)`,
            [
              `tv_${String(i)}`,
              IDS.tenantId,
              IDS.targetId,
              states[i],
              'agent_observation',
              JSON.stringify({ seq: i }),
              `2026-07-0${i + 1}T09:00:00+00:00`,
              'usr_owner',
              `aud_${String(i)}`,
            ],
          );
        }
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }

      const bundle = await repo.getTargetDetailBundle(CTX, IDS.targetId, {});
      assert.deepEqual(
        bundle.verification.history.map((row) => row.state),
        states,
        'history must stay oldest -> newest',
      );
      // "latest" is the last element; the DESC+reverse rewrite must not change it.
      assert.equal(bundle.verification.state, 'agent_verified');
      assert.equal(bundle.target.eligibility, 'eligible');
      // pending rows omit source_ref (existing contract).
      assert.equal(bundle.verification.history[0].source_ref, undefined);
    });
  });

  it('counts query round trips accurately via options.queryCounter', async () => {
    await withEphemeralPostgres(async (pool) => {
      await seedFindingsFixture(pool);
      const repo = createPortalRevampRepository(pool);

      const plain = { count: 0 };
      await repo.getTargetDetailBundle(CTX, IDS.targetId, { findings_limit: 5 }, {
        queryCounter: plain,
      });
      assert.equal(plain.count, 2, 'target lookup + batched fan-out');

      const page1 = await repo.getTargetDetailBundle(CTX, IDS.targetId, { findings_limit: 5 });
      const legacy = { count: 0 };
      await repo.getTargetDetailBundle(
        CTX,
        IDS.targetId,
        { findings_limit: 5, findings_cursor: encodeCursor({ id: page1.findings.at(-1).id }) },
        { queryCounter: legacy },
      );
      assert.equal(legacy.count, 3, 'legacy cursor adds one indexed resolution lookup');
    });
  });
});
