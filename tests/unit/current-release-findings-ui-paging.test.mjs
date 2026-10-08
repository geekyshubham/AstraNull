import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  FINDINGS_LIMIT_MAX,
  FINDING_SEVERITY_CLASSES,
  findingGroupCheckId,
  findingSeverityClass,
  findingStatusFilter,
  findingsComplete,
  findingsPath,
  findingsQuery,
  parseFindingsEnvelope,
} from '../../apps/web/react/src/lib/findings-query.mjs';

const read = (relative) => readFileSync(new URL(`../../apps/web/react/src/${relative}`, import.meta.url), 'utf8');

function between(source, start, end) {
  const from = source.indexOf(start);
  assert.ok(from >= 0, `missing ${start}`);
  const to = end ? source.indexOf(end, from + start.length) : source.length;
  assert.ok(to > from, `missing ${end} after ${start}`);
  return source.slice(from, to);
}

const pageComponents = read('pages/page-components.tsx');
const detail = read('pages/detail-pages.tsx');
const reportLive = between(detail, 'function ReportLiveOpenFindings(', 'export function ReportDetailPage(');
const findingsPage = read('pages/refined/findings-refined.tsx');
const dashboard = read('pages/dashboard-page.tsx');
const hooks = read('components/findings/use-server-findings.ts');
const originRelations = read('components/targets/origin-relations.tsx');
const targetDetail = read('pages/target-detail-view.tsx');

describe('findings list query: only predicates the server accepts', () => {
  it('sends one exact status, drops "all" and unknown statuses instead of inventing multi-status', () => {
    assert.equal(findingsQuery({ status: 'in_progress' }), 'status=in_progress');
    assert.equal(findingsQuery({ status: 'all' }), '');
    assert.equal(findingsQuery({ status: 'open,in_progress' }), '');
    assert.equal(findingsQuery({ status: 'remediation_pending' }), '');
    assert.equal(findingStatusFilter(' Accepted_Risk '), 'accepted_risk');
  });

  it('caps the page size at the server maximum and only sends page numbers after the first', () => {
    assert.equal(findingsQuery({ limit: 5000 }), `limit=${FINDINGS_LIMIT_MAX}`);
    assert.equal(FINDINGS_LIMIT_MAX, 200);
    assert.equal(findingsQuery({ limit: 0 }), '');
    assert.equal(findingsQuery({ limit: 25, page: 1 }), 'limit=25');
    assert.equal(findingsQuery({ limit: 25, page: 2 }), 'limit=25&page=2');
    assert.equal(findingsQuery({ page: 1.5 }), '');
  });

  it('drops malformed ids, severities and searches so an address never becomes a 400', () => {
    assert.equal(findingsQuery({ target_group_id: 'tg_checkout', target_id: 'bad id', check_id: 'all' }), 'target_group_id=tg_checkout');
    assert.equal(findingsQuery({ severity: 'S2' }), 'severity=high');
    assert.equal(findingsQuery({ severity: 'weird-token' }), 'severity=unknown');
    assert.equal(findingsQuery({ severity: 'all' }), '');
    assert.equal(findingsQuery({ severity: 'x'.repeat(33) }), '');
    assert.equal(findingsQuery({ q: 'needle\u0007' }), '');
    assert.equal(findingsQuery({ q: 'x'.repeat(201) }), '');
    assert.equal(findingsQuery({ q: '  origin  ' }), 'q=origin');
    assert.equal(findingsPath({ test_run_id: 'run_1', status: 'open' }), '/v1/findings?status=open&test_run_id=run_1');
    assert.equal(findingsPath({}), '/v1/findings');
  });
});

describe('severity classes: the same folding the server compares on', () => {
  it('folds aliases to one class and leaves everything else unknown, never low', () => {
    assert.deepEqual(['S1', ' critical ', 's2', 'HIGH', 'moderate', 'S3', 's4', 'low', 'info'].map(findingSeverityClass), ['critical', 'critical', 'high', 'high', 'medium', 'medium', 'low', 'low', 'info']);
    assert.equal(findingSeverityClass('sev-9'), 'unknown');
    assert.equal(findingSeverityClass(''), 'unknown');
    assert.equal(findingSeverityClass(null), 'unknown');
    assert.deepEqual([...FINDING_SEVERITY_CLASSES], ['critical', 'high', 'medium', 'low', 'info', 'unknown']);
  });

  it('counts each dashboard bucket with one class query so aliases are not added twice', () => {
    assert.match(hooks, /critical: \['critical'\],\n  high: \['high'\],\n  medium: \['medium'\],\n  low: \['low', 'info'\],/);
    assert.doesNotMatch(hooks, /'s1'|'s2'|'s3'|'s4'/);
  });

  it('offers each class once in the findings severity filter', () => {
    assert.match(findingsPage, /FINDING_SEVERITY_CLASSES\.map\(\(value\) => \(\{ value, label: FINDING_SEVERITY_CLASS_LABELS\[value\] \}\)\)/);
    assert.match(findingsPage, /severityChoice\(initialFilters\.severity\)/);
  });
});

describe('findings list envelope: totals are the server predicate, never the page length', () => {
  it('keeps total, pages and has_more from the envelope', () => {
    const envelope = parseFindingsEnvelope({ items: [{ id: 'f1' }], count: 51, total: 51, page: 2, pages: 2, has_more: false, limit: 50, meta: { empty_reason: null } });
    assert.deepEqual(envelope, { items: [{ id: 'f1' }], total: 51, page: 2, pages: 2, limit: 50, hasMore: false, emptyReason: null, exact: true });
  });

  it('marks a bare array or a missing total as not exact instead of counting the rows', () => {
    const legacy = parseFindingsEnvelope([{ id: 'f1' }, { id: 'f2' }]);
    assert.equal(legacy.total, null);
    assert.equal(legacy.exact, false);
    assert.equal(legacy.items.length, 2);
    assert.equal(parseFindingsEnvelope({ items: [] }).exact, false);
  });

  it('derives pages from total and limit only when the server sent both', () => {
    assert.equal(parseFindingsEnvelope({ items: [], total: 101, limit: 50 }).pages, 3);
    assert.equal(parseFindingsEnvelope({ items: [], total: null, limit: 50 }).pages, null);
  });

  it('calls a read complete only when every matched row is loaded and no page remains', () => {
    const first = parseFindingsEnvelope({ items: new Array(50).fill({}), total: 51, page: 1, pages: 2, has_more: true, limit: 50 });
    assert.equal(findingsComplete(first, 50), false);
    const last = parseFindingsEnvelope({ items: [{}], total: 51, page: 2, pages: 2, has_more: false, limit: 50 });
    assert.equal(findingsComplete(last, 51), true);
    assert.equal(findingsComplete(parseFindingsEnvelope([{}]), 1), false);
    assert.equal(findingsComplete(null, 0), false);
  });

  it('recovers the exact check id from a group key and refuses unknown or malformed ones', () => {
    assert.equal(findingGroupCheckId(`${encodeURIComponent('origin.leak_scan.safe')}|${encodeURIComponent('Origin reachable')}`), 'origin.leak_scan.safe');
    assert.equal(findingGroupCheckId('unknown-check|issue'), '');
    assert.equal(findingGroupCheckId('no-separator'), '');
    assert.equal(findingGroupCheckId('%E0%A4%A|x'), '');
  });
});

describe('findings page: a linked predicate is exact', () => {
  it('replaces remembered filters and page with the linked predicate', () => {
    assert.match(findingsPage, /const \[urlPredicate\] = useState\(\(\) => Boolean\(urlStatus \|\| urlSeverity \|\| urlTarget\)\)/);
    assert.match(findingsPage, /urlPredicate \? 1 : Math\.max\(1, initial\.page \?\? 1\)/);
  });

  it('clears the linked predicate from the address only when the predicate itself changes', () => {
    assert.match(findingsPage, /const predicateKey = `\$\{statusFilter\}\|\$\{severityFilter\}\|\$\{targetFilter\}\|\$\{debouncedSearch\}`;/);
    assert.match(findingsPage, /if \(shownPredicate\.current === predicateKey\) return;/);
    assert.match(findingsPage, /replaceRouteParams\(\{ status: null, severity: null, target_id: null, target: null \}\)/);
  });

  it('keeps a linked group visible in the group filter even when it is not in the loaded list', () => {
    assert.match(findingsPage, /label: 'Unavailable domain'/);
  });
});

describe('report and dashboard: live counts come from server predicates', () => {
  it('reads open findings per captured run with an exact test_run_id predicate', () => {
    assert.match(reportLive, /status: 'open', test_run_id: id/);
    assert.match(reportLive, /useFindingPages\(/);
    assert.doesNotMatch(reportLive, /data\.findings/);
    assert.doesNotMatch(detail, /liveOpenLinked/);
  });

  it('says how far an evidence-to-finding lookup reached when only the loaded page was checked', () => {
    assert.match(detail, /older findings were not checked/);
  });

  it('labels the dashboard posture tally as partial when the open sample is not complete', () => {
    assert.match(dashboard, /a target tallied as passed may still have an older open finding/);
  });

  it('derives counts from rows only when the server says one read holds every match', () => {
    assert.match(hooks, /function completePage\(page: ServerFindingsPage\) \{\n  return page\.state === 'ready' && findingsComplete\(page\.envelope, page\.envelope\?\.items\.length \?\? 0\);/);
    assert.match(hooks, /const status = findingStatus\(row\);/);
    assert.match(hooks, /enabled && sample\.state !== 'loading' && !complete/);
    assert.match(hooks, /const key = findingSeverityClass\(row\.severity\);/);
    assert.match(dashboard, /useOpenFindingOverview\(config, session, findingsReload, 3, 8, openSample\)/);
  });

  it('reads several predicates a few at a time and never above the server page maximum', () => {
    assert.match(hooks, /const PREDICATE_BATCH = 6;/);
    assert.doesNotMatch(hooks, /limit: (?:5000|1000|500)\b/);
  });
});

describe('origin relations: approved checks from target-scoped reads', () => {
  it('reads compatible pairs and exact catalog definitions, not the global list', () => {
    assert.match(originRelations, /\/compatible-checks`/);
    assert.match(originRelations, /`\/v1\/checks\/\$\{encodeURIComponent\(id\)\}`/);
    assert.match(originRelations, /'setup_required'/);
    assert.match(originRelations, /'host_sni_bypass'/);
    assert.doesNotMatch(originRelations, /checks\.filter\(/);
    assert.doesNotMatch(targetDetail, /<OriginRelations[\s\S]{0,400}checks=\{checks\}/);
  });

  it('keeps loading, failed and empty states distinct and never claims an unavailable check', () => {
    assert.match(originRelations, /Loading the approved origin checks for this target\./);
    assert.match(originRelations, /Approved origin checks could not load/);
    assert.match(originRelations, /No approved origin check is available for this target\./);
    assert.match(originRelations, /Retry loading checks/);
  });
});

describe('target detail load errors: missing, denied and failed stay distinct', () => {
  const detailApi = read('lib/target-detail-api.ts');
  const detailView = read('pages/target-detail-view.tsx');

  it('never shows raw server text for a 5xx and reads a server empty reason only for a 4xx', () => {
    assert.match(detailApi, /status >= 400 && status < 500 \? getString\(payloadMeta, \['empty_reason'\]\) : ''/);
    assert.match(detailApi, /apiErrorMessage\(err, 'Target details could not load\.'\)/);
    assert.doesNotMatch(detailApi, /\|\| getString\(payload, \['error'\]\)\n\s+\|\| \(err instanceof Error/);
  });

  it('renders a failed read as an alert with Retry, apart from the shared missing and denied states', () => {
    assert.match(detailView, /kind="record-missing"/);
    assert.match(detailView, /kind="access-denied"/);
    assert.match(detailView, /<div role="alert" data-target-load-error="true">/);
    assert.match(detailView, /title="Target details could not load\."/);
    assert.match(detailView, /actionLabel="Retry"\n\s+onAction=\{\(\) => void reload\(\)\}/);
  });
});

describe('dashboard: authoritative declared scope and width-aware layout', () => {
  const dashboardCss = read('pages/dashboard-page.css');

  it('counts declared targets and hostnames from the server units, not the loaded rows', () => {
    assert.match(dashboard, /const serverRecords = finiteCount\(serverUnits\?\.target_records\);/);
    assert.match(dashboard, /const declaredTargets = serverRecords \?\? data\.targets\.length;/);
    assert.match(dashboard, /const loadedIsWholeScope = serverRecords === null \|\| data\.targets\.length === serverRecords;/);
    assert.match(dashboard, /`\/v1\/targets\?verification_state=\$\{state\}&unit=target&limit=1`/);
  });

  it('names each cohort count the way it is shown', () => {
    assert.match(dashboard, /: \$\{formatNumber\(part\.count\)\} \$\{unitNoun\}\. Open the matching list\./);
    assert.doesNotMatch(dashboard, /: \$\{part\.count\} \$\{unitNoun\}/);
  });

  it('reflows by the dashboard width so a docked inspector stacks the overview instead of squeezing it', () => {
    assert.match(dashboardCss, /\.dashboard-page \{ container: dashboard \/ inline-size; \}/);
    assert.match(dashboardCss, /@container dashboard \(max-width: 880px\)/);
    assert.match(dashboardCss, /@container dashboard \(max-width: 720px\)/);
    assert.match(dashboardCss, /@container dashboard \(max-width: 480px\)/);
    assert.doesNotMatch(dashboardCss, /@media \(max-width: (1100|900|560)px\)/);
    assert.match(dashboardCss, /\.an-dash-grid \.data-table \{ min-width: 32rem; \}/);
  });
});
