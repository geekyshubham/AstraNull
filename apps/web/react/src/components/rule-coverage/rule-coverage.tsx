import { useEffect, useMemo, useState } from 'react';
import { ArrowRight, Ban, CircleCheck, CircleDot, CircleDashed, CircleMinus, CircleSlash, CircleX, FilePlus, type LucideIcon } from 'lucide-react';
import { requestJson } from '../../lib/api';
import { apiErrorMessage } from '../../lib/error-messages';
import { buildDetailHref } from '../../lib/route-params';
import { formatDate } from '../../lib/utils';
import type { PortalConfig, Session } from '../../lib/types';
import { controlsHref, inlineDeclarationLabel } from '../../lib/control-declarations.mjs';
import { plainCheckName } from '../../lib/plain-language.mjs';
import {
  ASSURANCE_META,
  COVERAGE_STATUS_META,
  LAYER_META,
  assuranceCounts,
  coverageStatusCounts,
  filterCoverageByLayer,
  normalizeRuleCoverage,
  sortCoverageForAttention,
  type CoverageCategory,
  type CoverageStatusId,
} from '../../lib/rule-coverage.mjs';
import { AnchorButton, Button } from '../ui/button';
import { Badge } from '../ui/badge';
import './rule-coverage.css';

const STATUS_ICONS: Record<CoverageStatusId, LucideIcon> = {
  covered_pass: CircleCheck,
  covered_fail: CircleX,
  inconclusive: CircleMinus,
  needs_declaration: FilePlus,
  not_run: CircleDashed,
  not_assessable: Ban,
  out_of_scope: CircleSlash,
};

type LayerFilter = 'all' | 'waf' | 'nfw';
const MAX_VISIBLE_CHECKS = 4;

function StatusBadge({ category }: { category: CoverageCategory }) {
  if (!category.status) return null;
  const Icon = STATUS_ICONS[category.status as CoverageStatusId] ?? CircleDashed;
  return (
    <Badge tone={category.statusTone} className="rc-status" title={COVERAGE_STATUS_META[category.status as CoverageStatusId]?.description}>
      <Icon size={12} aria-hidden="true" />{category.statusLabel}
    </Badge>
  );
}

function CheckList({ category, mode }: { category: CoverageCategory; mode: 'catalog' | 'target' }) {
  if (!category.checks.length) return <span className="rc-muted">No check</span>;
  const visible = category.checks.slice(0, MAX_VISIBLE_CHECKS);
  const hidden = category.checks.slice(MAX_VISIBLE_CHECKS);
  const item = (check: CoverageCategory['checks'][number]) => {
    const assurance = check.assurance === category.assurance ? '' : ASSURANCE_META[check.assurance as keyof typeof ASSURANCE_META]?.label ?? 'Missing';
    const statusText = check.stale ? 'Older than the freshness window' : check.statusLabel || 'Not run';
    const status = mode !== 'target' || (!check.stale && !check.observedAt && statusText === category.statusLabel)
      ? ''
      : `${statusText}${check.observedAt && !check.stale ? `, ${formatDate(check.observedAt)}` : ''}`;
    const meta = [assurance, status].filter(Boolean).join(' · ');
    return (
      <li key={check.checkId}>
        {check.present
          ? <a className="detail-entity-link" href={buildDetailHref('check-detail', check.checkId)}>{plainCheckName(check.name)}</a>
          : <span>{check.checkId} <span className="rc-muted">(not in this catalog)</span></span>}
        {meta ? <span className="rc-check-meta">{meta}</span> : null}
      </li>
    );
  };
  return (
    <>
      <ul className="rc-checks">{visible.map(item)}</ul>
      {hidden.length ? (
        <details className="rc-more">
          <summary><span className="rc-more-show">{hidden.length} more {hidden.length === 1 ? 'check' : 'checks'}</span><span className="rc-more-hide">Hide checks</span></summary>
          <ul className="rc-checks">{hidden.map(item)}</ul>
        </details>
      ) : null}
    </>
  );
}

function NextStep({ category, mode, targetId, canWrite }: { category: CoverageCategory; mode: 'catalog' | 'target'; targetId: string; canWrite: boolean }) {
  if (category.reason) return <span className="rc-reason">{category.reason}</span>;
  if (mode === 'target' && category.ctas.length) {
    return (
      <span className="rc-ctas">
        {category.ctas.map((cta) => canWrite
          ? <AnchorButton key={cta.key} size="sm" variant="secondary" href={controlsHref(targetId, cta.section)}>{cta.cta}</AnchorButton>
          : <span key={cta.key} className="rc-reason">Needs {inlineDeclarationLabel(cta.label)}; ask an engineer or admin to set it up.</span>)}
        {category.missingWithoutCta ? <span className="rc-reason">Also needs {category.missingWithoutCta}.</span> : null}
      </span>
    );
  }
  if (mode === 'target' && category.missingWithoutCta) return <span className="rc-reason">Needs {category.missingWithoutCta} on this target.</span>;
  if (mode === 'catalog' && category.requiredSentence) return <span className="rc-reason">Needs on each target: {category.requiredSentence}.</span>;
  if (category.assurance === 'soc_only') return <span className="rc-reason">Covered by a request-only check: start it and the governed workflow records the outcome.</span>;
  const validateHref = `${buildDetailHref('target-detail', targetId)}&tab=validate`;
  if (mode === 'target' && category.status === 'not_run') return <a className="rc-link" href={validateHref}>Run covering checks<ArrowRight size={13} aria-hidden="true" /></a>;
  if (mode === 'target' && category.status === 'covered_fail') return <a className="rc-link" href={validateHref}>Review failing check<ArrowRight size={13} aria-hidden="true" /></a>;
  if (mode === 'target' && category.status === 'inconclusive') return <a className="rc-link" href={validateHref}>See why it is inconclusive<ArrowRight size={13} aria-hidden="true" /></a>;
  return <span className="rc-muted">—</span>;
}

export function RuleCoverageView({ payload, mode, targetId = '', canWrite = false }: { payload: unknown; mode: 'catalog' | 'target'; targetId?: string; canWrite?: boolean }) {
  const [layer, setLayer] = useState<LayerFilter>('all');
  const model = useMemo(() => normalizeRuleCoverage(payload), [payload]);
  const scoped = filterCoverageByLayer(model.categories, layer);
  const statusCounts = coverageStatusCounts(model.categories);
  const assurance = assuranceCounts(model.categories);
  const layers = (['waf', 'nfw'] as const).filter((id) => layer === 'all' || layer === id);

  if (!model.categories.length) {
    return <p className="rc-muted" role="status">The server returned no rule-coverage categories.</p>;
  }

  return (
    <div className="rc" data-mode={mode}>
      {mode === 'target' ? (
        <dl className="rc-summary" aria-label="Rule families by current status">
          {(['covered_fail', 'inconclusive', 'needs_declaration', 'covered_pass', 'not_run', 'not_assessable', 'out_of_scope'] as CoverageStatusId[]).map((id) => {
            const Icon = STATUS_ICONS[id];
            return (
              <div key={id} data-tone={statusCounts[id] ? COVERAGE_STATUS_META[id].tone : 'muted'}>
                <dt><Icon size={13} aria-hidden="true" />{COVERAGE_STATUS_META[id].label}</dt>
                <dd className="tabular-nums">{statusCounts[id]}</dd>
              </div>
            );
          })}
        </dl>
      ) : (
        <dl className="rc-summary" aria-label="Rule families by assurance level">
          {(Object.keys(ASSURANCE_META) as Array<keyof typeof ASSURANCE_META>).filter((id) => assurance[id]).map((id) => (
            <div key={id}><dt>{ASSURANCE_META[id].label}</dt><dd className="tabular-nums">{assurance[id]}</dd></div>
          ))}
        </dl>
      )}

      <div className="rc-toolbar">
        <div className="rc-filters" role="group" aria-label="Show rule families for">
          {([['all', 'All'], ['waf', LAYER_META.waf.label], ['nfw', LAYER_META.nfw.label]] as Array<[LayerFilter, string]>).map(([id, label]) => (
            <button key={id} type="button" className="rc-filter" aria-pressed={layer === id} onClick={() => setLayer(id)}>
              {label}<span className="tabular-nums">{filterCoverageByLayer(model.categories, id).length}</span>
            </button>
          ))}
        </div>
        {mode === 'target' && model.freshnessDays ? <span className="rc-muted">Status counts only results from the last {model.freshnessDays} days.</span> : null}
      </div>

      <details className="rc-legend" open={mode === 'catalog'}>
        <summary>What the assurance levels mean</summary>
        <dl>
          {(Object.keys(ASSURANCE_META) as Array<keyof typeof ASSURANCE_META>).map((id) => (
            <div key={id}><dt>{ASSURANCE_META[id].label}</dt><dd>{ASSURANCE_META[id].description}</dd></div>
          ))}
        </dl>
      </details>

      {layers.map((layerId) => {
        const rows = mode === 'target'
          ? sortCoverageForAttention(scoped.filter((category) => category.layer === layerId))
          : scoped.filter((category) => category.layer === layerId);
        if (!rows.length) return null;
        return (
          <section key={layerId} className="rc-layer" aria-labelledby={`rc-${mode}-${layerId}`}>
            <h3 id={`rc-${mode}-${layerId}`}>{LAYER_META[layerId].label} <span className="rc-muted">· {LAYER_META[layerId].description}</span></h3>
            <div className="table-wrap rc-table-wrap" role="region" aria-label={`${LAYER_META[layerId].label} rule coverage, scrollable`} tabIndex={0}>
              <table className="data-table rc-table">
                <caption className="sr-only">
                  {LAYER_META[layerId].label} rule families: the best assurance AstraNull can reach{mode === 'target' ? ', this target\'s current status' : ''}, the checks that cover each one and the next step.
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Rule family</th>
                    <th scope="col">Assurance</th>
                    {mode === 'target' ? <th scope="col">Status</th> : null}
                    <th scope="col">Covered by</th>
                    <th scope="col">Next step</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((category) => (
                    <tr key={category.id} data-status={category.status || undefined}>
                      <th scope="row">
                        <span className="rc-family">
                          <strong>{category.name}</strong>
                          {category.description ? <small>{category.description}</small> : null}
                        </span>
                      </th>
                      <td>
                        <Badge
                          tone={['verdict', 'violation_only'].includes(category.assurance) ? 'default' : 'muted'}
                          className={category.assurance === 'partial' ? 'rc-assurance-partial' : undefined}
                          title={ASSURANCE_META[category.assurance as keyof typeof ASSURANCE_META]?.description}
                        >
                          {category.assurance === 'partial' ? <CircleDot size={12} aria-hidden="true" /> : null}{category.assuranceLabel}
                        </Badge>
                        {mode === 'target' && category.assuranceReason ? <small className="rc-assurance-reason">{category.assuranceReason}</small> : null}
                      </td>
                      {mode === 'target' ? <td><StatusBadge category={category} /></td> : null}
                      <td><CheckList category={category} mode={mode} /></td>
                      <td><NextStep category={category} mode={mode} targetId={targetId} canWrite={canWrite} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
    </div>
  );
}

type LoadState = { key: string; status: 'loading' | 'ready' | 'error'; payload: unknown; error: string };

/** Fetches catalog or per-target rule coverage and renders it; never substitutes another target's data. */
export function RuleCoveragePanel({ config, session, targetId = '', canWrite = false, reloadKey = 0, headingLevel = 2 }: {
  config: PortalConfig; session: Session; targetId?: string; canWrite?: boolean; reloadKey?: number; headingLevel?: 2 | 3;
}) {
  const mode = targetId ? 'target' : 'catalog';
  const path = targetId ? `/v1/targets/${encodeURIComponent(targetId)}/rule-coverage` : '/v1/rule-coverage';
  const key = `${path}|${reloadKey}`;
  const [retry, setRetry] = useState(0);
  const [load, setLoad] = useState<LoadState>({ key: '', status: 'loading', payload: null, error: '' });
  useEffect(() => {
    let cancelled = false;
    setLoad({ key, status: 'loading', payload: null, error: '' });
    requestJson(config, session, path)
      .then((payload) => { if (!cancelled) setLoad({ key, status: 'ready', payload, error: '' }); })
      .catch((error) => { if (!cancelled) setLoad({ key, status: 'error', payload: null, error: apiErrorMessage(error, 'Rule coverage could not load.') }); });
    return () => { cancelled = true; };
  }, [config, session, path, key, retry]);
  const current = load.key === key ? load : { key, status: 'loading' as const, payload: null, error: '' };
  const Heading = headingLevel === 3 ? 'h3' : 'h2';
  const titleId = `rc-title-${mode}`;
  return (
    <section className="rc-panel" aria-labelledby={titleId} aria-busy={current.status === 'loading' || undefined}>
      <header className="rc-head">
        <Heading id={titleId}>Rule coverage</Heading>
        <p>
          {mode === 'target'
            ? 'What AstraNull can conclude from outside for each WAF and network-firewall rule family, and what to declare or run next.'
            : 'For each WAF and network-firewall rule family: the most AstraNull can conclude from outside-in evidence and which checks cover it. Pick a target to see its current status.'}
        </p>
      </header>
      {current.status === 'loading' ? (
        <div aria-hidden="true"><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /><div className="skeleton skeleton-row" /></div>
      ) : current.status === 'error' ? (
        <div className="form-banner error row-actions" role="alert">
          <span>{current.error} No coverage is shown in its place.</span>
          <Button size="sm" variant="secondary" onClick={() => setRetry((value) => value + 1)}>Retry</Button>
        </div>
      ) : (
        <RuleCoverageView payload={current.payload} mode={mode} targetId={targetId} canWrite={canWrite} />
      )}
    </section>
  );
}
