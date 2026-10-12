import { useEffect, useRef, useState } from 'react';
import { getProtectionValidationReport, type LayerEvidence, type MatrixPath, type ProtectionMatrix as Matrix, type ProtectionReport, type PvFailure } from '../../../lib/protection-validation-api';
import { sessionIdentity } from '../../../lib/api';
import type { PortalConfig, Session } from '../../../lib/types';
import { Button } from '../../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';
import { formatDate } from '../../../lib/utils';
import { Badge } from '../../ui/badge';
import {
  EXPECTED_BEHAVIOR_LABELS,
  findingExclusionView,
  compatibilityReasonLabels,
  FIREWALL_STATUS_LABELS,
  freshnessView,
  LAYER_DIMENSION_LABELS,
  LAYER_LABELS,
  labelFrom,
  layerStateLabel,
  layerStateTone,
  pathObservationLabels,
  PATH_OUTCOME_LABELS,
  PATH_OUTCOME_TONES,
  PROTECTION_LAYERS,
  RELATION_KIND_LABELS,
  toneFrom,
} from './presenter.mjs';
import { EvidenceRefList, FailureNotice, LimitationList } from './shared';
import './entry-paths.css';

const DIMENSIONS = ['declared_intent', 'vendor_detection', 'observed_enforcement', 'application_identity', 'suspected_bypass', 'confirmed_scoped_bypass'] as const;

function layerOf(path: MatrixPath, layer: string): LayerEvidence | null {
  return path.layers.find((item) => item.layer === layer) ?? null;
}

function pathExclusions(path: MatrixPath) {
  const items = path.scenarios.length ? path.scenarios : [path];
  return items.map((item) => ({ scenario: 'scenario' in item ? item.scenario : '', ...findingExclusionView(item, true) })).filter((item) => item.excluded);
}

function pathName(path: MatrixPath) {
  return path.entry_target_value || path.entry_target_id || 'Target not recorded';
}

/** Per-path, per-layer evidence read model; selecting a cell only reads what is already recorded. */
export function ProtectionMatrixTable({
  matrix,
  selectedPathId,
  selectedLayer,
  onSelect,
}: {
  matrix: Matrix;
  selectedPathId: string;
  selectedLayer: string;
  onSelect: (pathId: string, layer: string) => void;
}) {
  const detailHeading = useRef<HTMLHeadingElement>(null);
  const focusDetail = useRef(false);
  const paths = matrix.paths;
  const selectedPath = paths.find((path) => path.entry_path_id === selectedPathId) ?? null;
  const selected = selectedPath && selectedLayer ? layerOf(selectedPath, selectedLayer) : null;

  useEffect(() => {
    if (focusDetail.current && selectedPath) {
      focusDetail.current = false;
      detailHeading.current?.focus();
    }
  }, [selectedPath, selectedLayer]);

  function choose(pathId: string, layer: string) {
    focusDetail.current = true;
    onSelect(pathId, layer);
  }

  const untested = paths.filter((path) => ['not_tested', 'skipped', 'inconclusive'].includes(path.outcome)).length;
  const staleCount = paths.filter((path) => freshnessView(path.freshness).state === 'stale').length;

  return (
    <div className="pv-section">
      <div className="pv-badges">
        <Badge tone="muted">No connector required</Badge>
        {matrix.scope_complete === false ? <Badge tone="warn">Partial view: some paths or evidence exceed this view’s limit</Badge> : null}
        {untested ? <Badge tone="warn">Partial: {untested} of {paths.length} paths not conclusively tested</Badge> : null}
        {staleCount ? <Badge tone="warn">{staleCount} stale</Badge> : null}
      </div>
      <div className="pv-matrix-wrap" role="region" aria-label="Per-path and per-layer evidence, scrollable" tabIndex={0}>
        <table className="pv-matrix">
          <caption className="sr-only">Observed behavior per declared entry path and protection layer. Each layer is evaluated separately.</caption>
          <thead>
            <tr>
              <th scope="col">Entry path</th>
              <th scope="col">Path result</th>
              {PROTECTION_LAYERS.map((layer) => <th key={layer} scope="col">{LAYER_LABELS[layer]}</th>)}
            </tr>
          </thead>
          <tbody>
            {paths.map((path) => {
              const rowSelected = path.entry_path_id === selectedPathId;
              const fresh = freshnessView(path.freshness);
              return (
                <tr key={path.entry_path_id} aria-selected={rowSelected ? true : undefined}>
                  <th scope="row">
                    <button type="button" className="pv-cell-button" aria-pressed={rowSelected && !selectedLayer} onClick={() => choose(path.entry_path_id, '')}>
                      <span className="pv-cell-path pv-break">{pathName(path)}</span>
                      <span className="pv-cell-meta">{labelFrom(RELATION_KIND_LABELS, path.relation_kind)}{path.status === 'archived' ? ' · archived' : ''}</span>
                    </button>
                  </th>
                  <td>
                    <div className="pv-badges">
                      <Badge tone={toneFrom(PATH_OUTCOME_TONES, path.outcome)}>{labelFrom(PATH_OUTCOME_LABELS, path.outcome)}</Badge>
                      {fresh.state === 'stale' ? <Badge tone="warn">Stale</Badge> : null}
                      {pathExclusions(path).length ? <Badge tone="muted">Evidence excluded from findings</Badge> : null}
                    </div>
                    {path.observation ? <span className="td-muted small">{labelFrom(pathObservationLabels(path.relation_kind), path.observation)}</span> : null}
                  </td>
                  {PROTECTION_LAYERS.map((layer) => {
                    const evidence = layerOf(path, layer);
                    const pressed = rowSelected && selectedLayer === layer;
                    return (
                      <td key={layer}>
                        <button
                          type="button"
                          className="pv-cell-button"
                          aria-pressed={pressed}
                          aria-label={`${LAYER_LABELS[layer]} on ${pathName(path)}: ${layerStateLabel('observed_enforcement', evidence?.observed_enforcement || 'not_tested')}`}
                          onClick={() => choose(path.entry_path_id, layer)}
                        >
                          <Badge tone={layerStateTone('observed_enforcement', evidence?.observed_enforcement || 'not_tested')}>
                            {layerStateLabel('observed_enforcement', evidence?.observed_enforcement || 'not_tested')}
                          </Badge>
                          <span className="td-muted small">{evidence?.declared_intent === 'required' ? 'Required' : evidence?.declared_intent === 'not_required' ? 'Not required' : 'Not declared'}</span>
                        </button>
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {selectedPath ? (
        <section className="pv-detail" aria-labelledby="pv-matrix-detail-title">
          <h3 id="pv-matrix-detail-title" ref={detailHeading} tabIndex={-1}>
            {selected ? `${LAYER_LABELS[selected.layer as keyof typeof LAYER_LABELS] ?? selected.layer} on ` : ''}<span className="mono pv-break">{pathName(selectedPath)}</span>
          </h3>
          <dl className="pv-dl">
            <div className="pv-dl-row"><dt>Relation</dt><dd>{labelFrom(RELATION_KIND_LABELS, selectedPath.relation_kind)}</dd></div>
            <div className="pv-dl-row"><dt>Expected behavior</dt><dd>{labelFrom(EXPECTED_BEHAVIOR_LABELS, selectedPath.expected_behavior)}</dd></div>
            <div className="pv-dl-row"><dt>Path result</dt><dd>{labelFrom(PATH_OUTCOME_LABELS, selectedPath.outcome)}</dd></div>
            {selectedPath.observation ? <div className="pv-dl-row"><dt>Entry observation</dt><dd>{labelFrom(pathObservationLabels(selectedPath.relation_kind), selectedPath.observation)}</dd></div> : null}
            <div className="pv-dl-row"><dt>Attribution</dt><dd>{selectedPath.attribution === 'attributed' ? 'Attributed by evidence' : 'Not attributed to a specific layer'}</dd></div>
            <div className="pv-dl-row"><dt>Freshness</dt><dd>{freshnessView(selectedPath.freshness).label}</dd></div>
            {selected ? DIMENSIONS.map((dimension) => (
              <div key={dimension} className="pv-dl-row">
                <dt>{LAYER_DIMENSION_LABELS[dimension]}</dt>
                <dd>{layerStateLabel(dimension, selected[dimension] || (dimension === 'declared_intent' ? 'undeclared' : dimension === 'vendor_detection' || dimension.endsWith('bypass') ? 'unknown' : 'not_tested'))}</dd>
              </div>
            )) : null}
          </dl>
          {pathExclusions(selectedPath).length ? (
            <div className="pv-notice" data-tone="warn" data-state="ignored-for-findings">
              <div><strong>Excluded from findings</strong><p>Unavailable evidence does not create or update a finding. This path stays visible in unknown or not-tested coverage; exclusion is not a passing result.</p>
                <ul>{pathExclusions(selectedPath).map((item, index) => <li key={`${item.scenario}-${index}`}>{item.scenario ? <code>{item.scenario}: </code> : null}{item.reason}</li>)}</ul>
              </div>
            </div>
          ) : null}
          {selected ? (
            <section className="pv-section" aria-label="Optional configuration context">
              <h4>Optional configuration context — explanation only</h4>
              <p className="td-muted small">Snapshot configuration explains declarations only. It never changes the observed result, supplies missing evidence, establishes protection or authorizes execution. Missing configuration remains unknown.</p>
              {matrix.configuration_access === 'redacted' ? <p className="td-muted small">Your role cannot read connector configuration.</p>
                : matrix.configuration_access === 'disabled' ? <p className="td-muted small">Optional connectors are disabled. External validation does not require them.</p>
                : selected.configuration ? (
                  <dl className="pv-dl">
                    <div className="pv-dl-row"><dt>Configuration state</dt><dd>{labelFrom({}, selected.configuration.status)}</dd></div>
                    <div className="pv-dl-row"><dt>Reported policy coverage</dt><dd>{labelFrom({}, selected.configuration.coverage)} — configuration, not measured behavior</dd></div>
                    <div className="pv-dl-row"><dt>Snapshot records</dt><dd>{selected.configuration.record_count ?? 'Not reported'}</dd></div>
                    <div className="pv-dl-row"><dt>Provider labels</dt><dd>{selected.configuration.provider_labels.join(', ') || 'Not reported'}</dd></div>
                    <div className="pv-dl-row"><dt>Snapshot limitations</dt><dd>{selected.configuration.markers.map((value) => labelFrom({}, value)).join(' · ') || 'None reported; completeness is not established'}</dd></div>
                  </dl>
                ) : <p className="td-muted small">No permitted explanation-only configuration is available.</p>}
            </section>
          ) : null}
          {selected?.layer === 'ddos' ? <p className="td-muted small">A bounded external check never establishes DDoS capacity or resilience.</p> : null}
          <LimitationList values={selected ? selected.evidence_limitations : selectedPath.limitations} />
          <h4>Evidence</h4>
          <EvidenceRefList refs={selected ? selected.evidence_refs : selectedPath.evidence_refs} focusPrefix={`pv-matrix-${selectedPath.entry_path_id}`} />
          {selected?.freshness && (selected.freshness as { captured_at?: string }).captured_at ? <p className="td-muted small">Captured {formatDate((selected.freshness as { captured_at?: string }).captured_at)}</p> : null}
        </section>
      ) : (
        <p className="td-muted small">Select a path or a layer cell to inspect its recorded evidence. Selecting reads results only; it never starts a check.</p>
      )}
    </div>
  );
}


type ReportState = { key: string; state: 'loading' } | { key: string; state: 'ready'; value: ProtectionReport } | { key: string; state: 'failed'; failure: PvFailure };

/** Current passive projection, deliberately separate from sealed generated snapshots. */
export function ProtectionValidationReportPanel({ config, session }: { config: PortalConfig; session: Session }) {
  const key = `${sessionIdentity(session)}|${config.authMode}`;
  const [stored, setStored] = useState<ReportState>({ key, state: 'loading' });
  const [reload, setReload] = useState(0);
  const state: ReportState = stored.key === key ? stored : { key, state: 'loading' };
  useEffect(() => {
    let current = true;
    const controller = new AbortController();
    setStored({ key, state: 'loading' });
    void getProtectionValidationReport(config, session, controller.signal).then((result) => {
      if (!current) return;
      if (result.state !== 'ready') setStored({ key, state: 'failed', failure: result });
      else if (result.value.tenant_id !== session.tenant_id) setStored({ key, state: 'failed', failure: { state: 'unavailable', code: 'scope_mismatch', status: 400, message: 'The report did not match this workspace. No other report was substituted.' } });
      else setStored({ key, state: 'ready', value: result.value });
    }).catch(() => { if (current) setStored({ key, state: 'failed', failure: { state: 'transport_error', message: 'Current protection validation could not load. No check was started.' } }); });
    return () => { current = false; controller.abort(); };
  }, [config, session, key, reload]);
  const report = state.state === 'ready' ? state.value : null;
  return (
    <Card className="protection-validation-report" role="region" aria-label="Current protection validation report">
      <CardHeader><div><CardTitle>Current protection validation</CardTitle><CardDescription>Passive current coverage, not a generated or sealed report snapshot. Reading and refreshing send no probe traffic and create no findings.</CardDescription></div>
        <Button size="sm" variant="secondary" disabled={state.state === 'loading'} onClick={() => setReload((value) => value + 1)}>Refresh current coverage</Button>
      </CardHeader>
      <CardContent className="pv-section">
        {state.state === 'loading' ? <p role="status">Loading current protection validation…</p> : null}
        {state.state === 'failed' ? <FailureNotice failure={state.failure} subject="current protection validation" onRetry={() => setReload((value) => value + 1)} /> : null}
        {report ? <>
          <p className="muted small">Read at {formatDate(report.generated_at)}. Results below are retained immutable comparisons; they are not a claim of current protection.</p>
          {report.source_records_complete !== true || report.conclusions_truncated ? <p className="pv-notice" data-tone="warn">Partial view: source records or conclusion listings are incomplete. Missing rows are not validated coverage.</p> : null}
          <p>{report.unknown_statement || 'Unknown and not-tested coverage remains visible. Missing evidence does not create findings or count as validated.'}</p>
          {report.incomplete_reasons.length ? <p className="pv-notice pv-break" data-tone="warn">Incomplete coverage: {report.incomplete_reasons.map((value) => labelFrom({}, value)).join(' · ')}</p> : null}
          {Object.keys(report.unknown_reasons).length ? <ul aria-label="Unknown coverage reasons">{Object.entries(report.unknown_reasons).map(([reason, count]) => <li key={reason}>{labelFrom({}, reason)}: {count}</li>)}</ul> : null}
          {[['Not-tested entry paths', report.not_tested_paths], ['Not-tested firewall expectations', report.untested_firewall_expectations]].map(([label, raw]) => {
            const coverage = raw as ProtectionReport['not_tested_paths'];
            return coverage.ids.length || coverage.total ? <p key={String(label)} className="pv-break"><strong>{String(label)}</strong>: {coverage.ids.join(', ') || 'Identifiers not listed'}{coverage.truncated ? ` (partial identifiers; ${coverage.total ?? 'unknown'} total)` : ''}</p> : null;
          })}
          {report.conclusions.length ? <div className="pv-matrix-wrap" role="region" aria-label="Protection validation conclusions, scrollable" tabIndex={0}>
            <table className="pv-matrix">
              <caption className="sr-only">Every available conclusion, including results excluded from findings. Finding use and current assurance are independent.</caption>
              <thead><tr><th scope="col">Subject / scenario</th><th scope="col">Retained result</th><th scope="col">Finding use</th><th scope="col">Current assurance</th></tr></thead>
              <tbody>{report.conclusions.map((item) => {
                const excluded = findingExclusionView(item);
                return <tr key={item.id} data-conclusion-id={item.id}>
                  <th scope="row" className="pv-break">{item.subject.entry_path_id || item.subject.expectation_id || item.id}{item.scenario ? <div>{item.scenario}</div> : null}</th>
                  <td>{labelFrom(item.comparison_kind === 'firewall_change' ? FIREWALL_STATUS_LABELS : PATH_OUTCOME_LABELS, item.result)}</td>
                  <td>{excluded.excluded ? <><strong>Excluded from findings</strong><p>{excluded.reason}</p><small>Does not create or update findings. Not a passing result.</small></> : item.ignored_for_findings === false ? 'Not excluded by the report; this does not prove that a finding exists.' : 'Finding eligibility not recorded'}</td>
                  <td>{labelFrom({}, item.current_assurance?.status || 'unknown')}{item.current_assurance?.reasons.length ? <p>{compatibilityReasonLabels(item.current_assurance.reasons).map((reason) => reason.label).join(' · ')}</p> : null}
                    <p>{item.readiness_eligible === true ? 'Eligible only for the report’s bounded readiness scope.' : item.readiness_eligible === false ? `Excluded from readiness: ${labelFrom({}, item.readiness_exclusion_reason || 'reason_not_recorded')}` : 'Readiness eligibility not recorded'}</p>
                  </td>
                </tr>;
              })}</tbody>
            </table>
          </div> : <p>No comparison conclusions are recorded. Unknown and not-tested declarations above are not hidden.</p>}
          {report.conclusions_truncated ? <p className="muted small">Showing {report.conclusions.length} of {report.conclusions_total ?? 'an unknown number of'} conclusions.</p> : null}
        </> : null}
      </CardContent>
    </Card>
  );
}
