import { useMemo, useState, type ReactNode } from 'react';
import { ChevronRight, Search, ShieldCheck, TriangleAlert } from 'lucide-react';
import { RESOURCE_FAMILIES, resourceFamilyCheckIds, resourceMatrixTargets } from '../../lib/resource-matrix.mjs';
import {
  ATTACK_FAMILIES,
  attackFamilyCheckIds,
  COVERAGE_OUTCOME_LABEL,
  COVERAGE_OUTCOME_TONE,
  coverageCell,
  openFindingChecksByTarget,
  rollUpCoverage,
  rowHasResult,
  type CoverageCell,
} from '../../lib/coverage-tree.mjs';
import { subdomainParentMap } from '../../lib/subdomain-grouping';
// @ts-ignore Plain ESM keeps executive labels directly testable with node:test.
import { plainCheckName } from '../../lib/plain-language.mjs';
import { formatNumber, pluralize } from '../../lib/utils';
import { EmptyState } from '../ui/empty-state';
import './charts.css';

type Rec = Record<string, unknown>;
type View = 'attack' | 'resource';
type Column = { key: string; label: string; checkIds: Set<string> };
type Node = { id: string; name: string; kind: string; children: Node[]; own: CoverageCell[]; total: CoverageCell[]; descendants: number };

const VIEW_OPTIONS: ReadonlyArray<{ id: View; label: string }> = [
  { id: 'attack', label: 'Attack type' },
  { id: 'resource', label: 'Resource exhausted' },
];

const LEGEND: ReadonlyArray<keyof typeof COVERAGE_OUTCOME_LABEL> = ['pass', 'gap', 'review', 'untested'];

function str(item: Rec, key: string) {
  const value = item[key];
  return typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value);
}

function supportsKind(check: Rec, kind: string) {
  const supported = Array.isArray(check.supported_targets) ? check.supported_targets.map((value) => String(value).toLowerCase()) : [];
  return supported.length === 0 || supported.includes(kind);
}

function cellSub(cell: CoverageCell, isParent: boolean) {
  if (cell.outcome === 'na') return '';
  if (isParent) return `${formatNumber(cell.testedHosts)} of ${formatNumber(cell.hosts)} hosts`;
  if (cell.outcome === 'untested') return '';
  return `${formatNumber(cell.testedChecks)}/${formatNumber(cell.applicableChecks)} checks`;
}

function nodeMatches(node: Node, query: string): boolean {
  return node.name.toLowerCase().includes(query) || node.children.some((child) => nodeMatches(child, query));
}

export function CoverageTree({
  checks,
  targets,
  runs,
  evidence,
  openFindings,
  loadError,
  onRetry,
}: {
  checks: Rec[];
  targets: Rec[];
  runs: Rec[];
  evidence: Rec[];
  openFindings: Rec[];
  loadError?: string | null;
  onRetry?: () => void;
}) {
  const [view, setView] = useState<View>('attack');
  const [query, setQuery] = useState('');
  const [onlyTested, setOnlyTested] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [showAllChildren, setShowAllChildren] = useState<Set<string>>(() => new Set());

  const columns = useMemo<Column[]>(() => (view === 'attack'
    ? ATTACK_FAMILIES.map((family) => ({ key: family.id, label: family.label, checkIds: attackFamilyCheckIds(checks, family) }))
    : RESOURCE_FAMILIES.map((family) => ({ key: family.id, label: plainCheckName(family.label), checkIds: resourceFamilyCheckIds(checks, family) }))
  ), [view, checks]);

  const roots = useMemo<Node[]>(() => {
    const active = resourceMatrixTargets(targets);
    const checkById = new Map(checks.map((check) => [str(check, 'check_id') || str(check, 'id'), check] as const));
    const openByTarget = openFindingChecksByTarget(openFindings);
    const parents = subdomainParentMap(active);
    const nodes = new Map<string, Node>();
    for (const target of active) {
      const id = str(target, 'id');
      if (!id) continue;
      const kind = str(target, 'kind').toLowerCase();
      const own = columns.map((column) => coverageCell({
        checkIds: new Set([...column.checkIds].filter((checkId) => {
          const check = checkById.get(checkId);
          return check ? supportsKind(check, kind) : false;
        })),
        targetId: id,
        runs,
        evidence,
        openChecks: openByTarget.get(id),
      }));
      nodes.set(id, { id, name: str(target, 'value') || id, kind, children: [], own, total: own, descendants: 0 });
    }
    const top: Node[] = [];
    for (const node of nodes.values()) {
      const parent = nodes.get(parents.get(node.id) ?? '');
      if (parent) parent.children.push(node);
      else top.push(node);
    }
    const settle = (node: Node): Node => {
      node.children.forEach(settle);
      node.children.sort((left, right) => Number(rowHasResult(right.total)) - Number(rowHasResult(left.total)) || left.name.localeCompare(right.name));
      node.descendants = node.children.reduce((sum, child) => sum + 1 + child.descendants, 0);
      node.total = node.own.map((cell, index) => rollUpCoverage([cell, ...node.children.map((child) => child.total[index])]));
      return node;
    };
    return top.map(settle).sort((left, right) => left.name.localeCompare(right.name));
  }, [targets, checks, columns, runs, evidence, openFindings]);

  if (loadError) {
    return <EmptyState icon={TriangleAlert} title="Coverage unavailable." body="Targets, checks or runs did not load, so no coverage is shown." actionLabel="Retry" onAction={onRetry} />;
  }
  if (roots.length === 0) {
    return <EmptyState icon={ShieldCheck} title="No declared domains yet." body="Declare a domain to see which attack types and resources have evidence." actionHref="#targets?add=1" actionLabel="Add target" />;
  }

  const search = query.trim().toLowerCase();
  const tested = roots.filter((node) => rowHasResult(node.total));
  const filterTested = onlyTested && tested.length > 0;
  const visible = roots.filter((node) => (!filterTested || rowHasResult(node.total)) && (!search || nodeMatches(node, search)));
  const hiddenUntested = filterTested ? roots.length - tested.length : 0;

  function toggle(id: string) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function renderRows(node: Node, depth: number): ReactNode[] {
    const isParent = node.children.length > 0;
    const open = isParent && (expanded.has(node.id) || (search !== '' && node.children.some((child) => nodeMatches(child, search))));
    const matching = open ? node.children.filter((child) => !search || nodeMatches(child, search) || node.name.toLowerCase().includes(search)) : [];
    const children = filterTested && !search && !showAllChildren.has(node.id) ? matching.filter((child) => rowHasResult(child.total)) : matching;
    const hiddenChildren = matching.length - children.length;
    return [
      <tr key={node.id} data-depth={depth}>
        <th scope="row">
          <span className="ctree-name" style={{ paddingInlineStart: `calc(${depth} * var(--space-6))` }}>
            {isParent ? (
              <button
                type="button"
                className="ctree-toggle"
                aria-expanded={open}
                aria-label={`${open ? 'Collapse' : 'Expand'} ${formatNumber(node.descendants)} ${pluralize(node.descendants, 'subdomain')} of ${node.name}`}
                onClick={() => toggle(node.id)}
              >
                <ChevronRight size={14} aria-hidden="true" data-open={open || undefined} />
              </button>
            ) : <span className="ctree-toggle-spacer" aria-hidden="true" />}
            <a className="ctree-host detail-entity-link" href={`#target-detail?id=${encodeURIComponent(node.id)}&tab=coverage`} title={node.name} data-depth={depth}>{node.name}</a>
            {isParent ? <span className="ctree-count">{formatNumber(node.descendants)}</span> : null}
          </span>
        </th>
        {(isParent ? node.total : node.own).map((cell, index) => {
          const label = COVERAGE_OUTCOME_LABEL[cell.outcome];
          const sub = cellSub(cell, isParent);
          return (
            <td key={columns[index].key}>
              <span
                className={`heatmap-cell heatmap-${COVERAGE_OUTCOME_TONE[cell.outcome]} matrix-cell ctree-cell`}
                data-outcome={cell.outcome}
                aria-label={`${node.name}, ${columns[index].label}: ${label}${sub ? `, ${sub}` : ''}`}
              >
                <strong>{cell.outcome === 'na' ? '—' : label}</strong>
                {sub ? <small>{sub}</small> : null}
              </span>
            </td>
          );
        })}
      </tr>,
      ...children.flatMap((child) => renderRows(child, depth + 1)),
      ...(hiddenChildren > 0 ? [
        <tr key={`${node.id}-more`} className="ctree-more">
          <td colSpan={columns.length + 1}>
            <button
              type="button"
              className="link-button"
              style={{ marginInlineStart: `calc(${depth + 1} * var(--space-6) + 28px)` }}
              onClick={() => setShowAllChildren((current) => new Set(current).add(node.id))}
            >
              {`Show ${formatNumber(hiddenChildren)} ${pluralize(hiddenChildren, 'subdomain')} with no results`}
            </button>
          </td>
        </tr>
      ] : []),
    ];
  }

  return (
    <div className="ctree">
      <div className="ctree-toolbar">
        <div className="ctree-view" role="group" aria-label="Group coverage by">
          {VIEW_OPTIONS.map((option) => (
            <button key={option.id} type="button" aria-pressed={view === option.id} onClick={() => setView(option.id)}>{option.label}</button>
          ))}
        </div>
        <label className="ctree-search">
          <Search size={15} aria-hidden="true" />
          <span className="sr-only">Find a domain or subdomain</span>
          <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find a domain" />
        </label>
        {tested.length > 0 ? (
          <label className="ctree-only">
            <input type="checkbox" checked={onlyTested} onChange={(event) => setOnlyTested(event.target.checked)} />
            Only hosts with results
          </label>
        ) : null}
      </div>
      {visible.length === 0 ? (
        <p className="matrix-footnote">No domain matches “{query.trim()}”.</p>
      ) : (
        <div className="heatmap" role="region" tabIndex={0} aria-label={`Coverage by domain, grouped by ${view === 'attack' ? 'attack type' : 'resource exhausted'}`}>
          <table className={`matrix-table ctree-table${view === 'resource' ? ' matrix-table--resource' : ''}`}>
            <caption className="sr-only">Coverage for {formatNumber(visible.length)} domains. Expand a domain to see its subdomains.</caption>
            <thead>
              <tr>
                <th scope="col"><span className="heatmap-head matrix-corner">Domain</span></th>
                {columns.map((column) => <th scope="col" key={column.key}><span className="heatmap-head">{column.label}</span></th>)}
              </tr>
            </thead>
            <tbody>{visible.flatMap((node) => renderRows(node, 0))}</tbody>
          </table>
        </div>
      )}
      <div className="ctree-foot">
        <ul className="ctree-legend" aria-label="Legend">
          {LEGEND.map((outcome) => (
            <li key={outcome}><span className={`ctree-swatch heatmap-${COVERAGE_OUTCOME_TONE[outcome]}`} data-outcome={outcome} aria-hidden="true" />{COVERAGE_OUTCOME_LABEL[outcome]}</li>
          ))}
        </ul>
        {hiddenUntested > 0 && !search ? (
          <button type="button" className="link-button" onClick={() => setOnlyTested(false)}>
            {`Show ${formatNumber(hiddenUntested)} ${pluralize(hiddenUntested, 'domain')} with no results yet`}
          </button>
        ) : null}
      </div>
    </div>
  );
}
