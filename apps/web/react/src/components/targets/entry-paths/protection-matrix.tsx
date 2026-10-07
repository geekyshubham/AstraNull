import { useEffect, useRef } from 'react';
import type { LayerEvidence, MatrixPath, ProtectionMatrix as Matrix } from '../../../lib/protection-validation-api';
import { formatDate } from '../../../lib/utils';
import { Badge } from '../../ui/badge';
import {
  EXPECTED_BEHAVIOR_LABELS,
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
import { EvidenceRefList, LimitationList } from './shared';

const DIMENSIONS = ['declared_intent', 'vendor_detection', 'observed_enforcement', 'application_identity', 'suspected_bypass', 'confirmed_scoped_bypass'] as const;

function layerOf(path: MatrixPath, layer: string): LayerEvidence | null {
  return path.layers.find((item) => item.layer === layer) ?? null;
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
