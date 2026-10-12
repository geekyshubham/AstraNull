import { buildGetStatePayload } from '../../lib/statePayload.mjs';
import { projectReadiness, verifiedVerdicts } from '../../lib/readinessProjection.mjs';

const TEST_RUN_LIST_LIMIT = 500;
const EVIDENCE_LIST_LIMIT = 500;
const RUN_EVENTS_LIMIT = 1000;
const RUN_EVENT_FETCH_RUN_LIMIT = 30;
const RECENT_RUNS_LIMIT = 5;
export const STATE_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['listTargetGroups', 'listTargets']);
export const STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze(['listTestRuns', 'loadRunEvidenceBatch', 'listEvidence', 'countOpenFindings']);
export const STATE_HIGH_SCALE_REPOSITORY_METHODS = Object.freeze(['listHighScaleRequests']);
export const STATE_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze(['getKillSwitchRecord']);
export const POSTGRES_STATE_SERVICE_METHODS = Object.freeze(['getState']);

function assertStateRepositories(repositories) {
  for (const [name, methods] of [['coreCatalog', STATE_CORE_CATALOG_REPOSITORY_METHODS], ['validationEvidence', STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS], ['highScale', STATE_HIGH_SCALE_REPOSITORY_METHODS], ['killSwitch', STATE_KILL_SWITCH_REPOSITORY_METHODS]]) {
    if (!repositories?.[name]) throw new Error(`Postgres state service adapter requires repositories.${name}.`);
    for (const method of methods) if (typeof repositories[name][method] !== 'function') throw new Error(`Postgres state service adapter requires ${name}.${method}().`);
  }
}

function sortRunsNewestFirst(runs) {
  return [...runs].sort((a, b) => String(b.started_at ?? b.created_at ?? '').localeCompare(String(a.started_at ?? a.created_at ?? '')) || String(b.id).localeCompare(String(a.id)));
}
function sanitizeKillSwitchRecord(record, tenantId) {
  return { tenant_id: record?.tenant_id ?? tenantId, active: Boolean(record?.active), reason: record?.reason ?? null, updated_at: record?.updated_at ?? null, updated_by: record?.updated_by ?? null };
}

export function createPostgresStateServices(repositories, options = {}) {
  assertStateRepositories(repositories);
  const { coreCatalog, validationEvidence, highScale, killSwitch } = repositories;
  const nowFn = options.now ?? (() => new Date());
  return {
    async queryAuditEntries(ctx, query = {}) {
      if (typeof repositories.audit?.queryAuditEntries !== 'function') {
        const error = new Error('Audit reads are not wired.');
        error.status = 503; error.code = 'postgres_route_not_wired'; throw error;
      }
      return repositories.audit.queryAuditEntries(ctx, query);
    },
    async getAuditEntry(ctx, id) {
      if (typeof repositories.audit?.getAuditEntry !== 'function') {
        const error = new Error('Audit reads are not wired.');
        error.status = 503; error.code = 'postgres_route_not_wired'; throw error;
      }
      return repositories.audit.getAuditEntry(ctx, id);
    },
    async getState(ctx) {
      const tenantId = ctx.tenantId;
      const asOf = nowFn();
      const inputPromise = typeof validationEvidence.readReadinessInputs === 'function'
        ? validationEvidence.readReadinessInputs(ctx, { asOf }) : Promise.resolve(null);
      // Complete scope is returned in the same statement snapshot as the evidence.
      // Do not hydrate group list pages (finding/LOA joins) merely to count or assess scope.
      const scopePromise = inputPromise.then((input) => input?.scope_complete === true && Array.isArray(input.groups) && Array.isArray(input.targets)
        ? [input.groups, input.targets] : Promise.all([coreCatalog.listTargetGroups(ctx), coreCatalog.listTargets(ctx)]));
      const [[groups, targets], feedRuns, evidenceItems, openFindingsCount, highScaleRequests, killSwitchRecord, completeInputs, tenant] = await Promise.all([
        scopePromise,
        validationEvidence.listTestRuns(ctx, { limit: TEST_RUN_LIST_LIMIT }),
        validationEvidence.listEvidence(ctx, { limit: EVIDENCE_LIST_LIMIT }),
        validationEvidence.countOpenFindings(ctx), highScale.listHighScaleRequests(ctx), killSwitch.getKillSwitchRecord(ctx),
        inputPromise,
        typeof coreCatalog.getCurrentTenant === 'function' ? coreCatalog.getCurrentTenant(ctx) : null,
      ]);
      const sortedRuns = sortRunsNewestFirst(feedRuns);
      let inputs = completeInputs;
      if (!inputs) {
        // Compatibility readers are capped presentation feeds, not an estate assessment.
        const eligibleRuns = feedRuns.filter((run) => ['completed', 'verdicted'].includes(run.status));
        const eventRunIds = new Set(sortedRuns.filter((run) => ['completed', 'verdicted'].includes(run.status)).slice(0, RUN_EVENT_FETCH_RUN_LIMIT).map((run) => run.id));
        for (const item of evidenceItems) if (item.related_event_id && item.test_run_id) eventRunIds.add(item.test_run_id);
        const batch = await validationEvidence.loadRunEvidenceBatch(ctx, { runIds: eligibleRuns.map((run) => run.id), eventRunIds: sortedRuns.filter((run) => eventRunIds.has(run.id)).map((run) => run.id), eventLimitPerRun: RUN_EVENTS_LIMIT });
        inputs = { runs: feedRuns, verdicts: batch?.verdicts ?? [], events: batch?.events ?? [], evidenceItems, findings: [], input_complete: false };
      }
      const readiness = { ...projectReadiness({ ...inputs, tenantId, targets, groups, asOf, catalog: options.catalog, highScaleRequests, killSwitch: killSwitchRecord, legacy_snapshot: tenant?.dashboard_rollup?.readiness }), persistence: 'postgres' };
      const byRun = verifiedVerdicts({ ...inputs, tenantId, nowMs: asOf.getTime() });
      const scopedRequests = highScaleRequests.filter((row) => row.tenant_id === tenantId);
      return buildGetStatePayload({ tenantId, rollup: null, computed: {
        readiness, target_groups: groups.length,
        recent_runs: sortedRuns.slice(0, RECENT_RUNS_LIMIT).reverse().map((run) => ({ ...run, verdict: byRun.get(run.id)?.verdict ?? null })),
        open_findings: openFindingsCount, high_scale_requests: scopedRequests.length,
      }, killSwitch: sanitizeKillSwitchRecord(killSwitchRecord, tenantId), highScaleWired: true, highScaleRequests: scopedRequests });
    },
  };
}
