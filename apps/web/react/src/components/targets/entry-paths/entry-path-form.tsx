import { useEffect, useRef, useState } from 'react';
import { fetchTargetOriginBindings, type OriginBindingList } from '../../../lib/target-detail-api';
import type { TargetCandidate } from '../../../lib/protection-validation-api';
import type { DataItem, PortalConfig, Session } from '../../../lib/types';
import { Button } from '../../ui/button';
import {
  entryPathCreateBody,
  entryPathDraftErrors,
  EXPECTED_BEHAVIOR_LABELS,
  LAYER_LABELS,
  PROTECTION_LAYERS,
  RELATION_KIND_LABELS,
  type EntryPathCreateBody,
  type EntryPathDraft,
} from './presenter.mjs';
import { TargetCandidatePicker } from './target-candidate-picker';

export type EntryPathReview = { body: EntryPathCreateBody; entryLabel: string };

const EMPTY: EntryPathDraft = {
  relation_kind: '',
  entry_target_id: '',
  expected_behavior: '',
  required_layers: [],
  origin_binding_id: '',
  owner: '',
  purpose: '',
};

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

/** Inline declaration of one entry path; reviewing it sends nothing, and only existing declared targets or origin relations are offered. */
export function EntryPathForm({
  config,
  session,
  target,
  onCancel,
  onReview,
}: {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  onCancel: () => void;
  onReview: (review: EntryPathReview) => void;
}) {
  const targetId = str(target, 'id');
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [draft, setDraft] = useState<EntryPathDraft>(EMPTY);
  const [entryLabel, setEntryLabel] = useState('');
  const [errors, setErrors] = useState<Partial<Record<keyof EntryPathDraft, string>>>({});
  const [bindings, setBindings] = useState<OriginBindingList | null>(null);

  useEffect(() => { headingRef.current?.focus(); }, []);

  useEffect(() => {
    if (draft.relation_kind !== 'origin' || bindings) return undefined;
    const controller = new AbortController();
    fetchTargetOriginBindings(config, session, targetId, controller.signal).then((result) => {
      if (!controller.signal.aborted) setBindings(result);
    });
    return () => controller.abort();
  }, [config, session, targetId, draft.relation_kind, bindings]);

  const originRelations = bindings?.state === 'ready'
    ? bindings.items.filter((item) => str(item, 'protected_target_id') === targetId && str(item, 'status') === 'active')
    : [];

  function update(patch: Partial<EntryPathDraft>) {
    const kindChanged = patch.relation_kind !== undefined && patch.relation_kind !== draft.relation_kind;
    if (kindChanged) setEntryLabel(patch.relation_kind === 'primary_route' ? str(target, 'value') : '');
    setDraft((current) => {
      const next = { ...current, ...patch };
      if (kindChanged) {
        next.origin_binding_id = '';
        next.entry_target_id = patch.relation_kind === 'primary_route' ? targetId : '';
      }
      if (patch.expected_behavior === 'intentionally_public') next.required_layers = [];
      return next;
    });
  }

  function chooseBinding(bindingId: string) {
    const binding = originRelations.find((item) => str(item, 'id') === bindingId) ?? null;
    setDraft((current) => ({ ...current, origin_binding_id: bindingId, entry_target_id: str(binding, 'origin_target_id') }));
    setEntryLabel(str(binding, 'origin_target_id'));
  }

  function toggleLayer(layer: string, checked: boolean) {
    setDraft((current) => ({
      ...current,
      required_layers: checked ? [...new Set([...current.required_layers, layer])] : current.required_layers.filter((item) => item !== layer),
    }));
  }

  function submit() {
    const next = entryPathDraftErrors(draft, targetId);
    setErrors(next);
    const firstInvalid = Object.keys(next)[0];
    if (firstInvalid) {
      window.requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-pv-field="${firstInvalid}"] input, [data-pv-field="${firstInvalid}"] select, [data-pv-field="${firstInvalid}"] textarea`)?.focus());
      return;
    }
    onReview({ body: entryPathCreateBody(draft), entryLabel: entryLabel || draft.entry_target_id });
  }

  const kind = draft.relation_kind;
  const layersDisabled = draft.expected_behavior === 'intentionally_public';

  return (
    <form className="pv-form" noValidate onSubmit={(event) => { event.preventDefault(); submit(); }} aria-labelledby="pv-entry-form-title">
      <h3 id="pv-entry-form-title" ref={headingRef} tabIndex={-1}>Declare an entry path</h3>
      <p className="pv-copy">Record a route your users or attackers could reach this application through. A declaration sends no traffic and is not a protection result.</p>

      <label className="td-field" data-pv-field="relation_kind">
        <span>Relation</span>
        <select value={kind} aria-invalid={errors.relation_kind ? true : undefined} aria-describedby="pv-kind-help" onChange={(event) => update({ relation_kind: event.target.value })}>
          <option value="">Choose a relation</option>
          {Object.entries(RELATION_KIND_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <span id="pv-kind-help" className={errors.relation_kind ? 'td-form-error' : 'td-muted small'}>{errors.relation_kind ?? 'How this path relates to the application anchored on this target.'}</span>
      </label>

      {kind === 'primary_route' ? (
        <p className="td-muted small" data-pv-field="entry_target_id">The primary route is this target: <span className="mono pv-break">{str(target, 'value') || targetId}</span></p>
      ) : null}

      {kind === 'origin' ? (
        <label className="td-field" data-pv-field="origin_binding_id">
          <span>Declared origin relation</span>
          {bindings === null ? <div className="skeleton skeleton-row" aria-label="Loading origin relations" /> : null}
          {bindings?.state === 'unsupported' ? <span className="td-muted small">Origin relations are not available from this server yet.</span> : null}
          {bindings?.state === 'unavailable' ? <span className="td-form-error small" role="alert">{bindings.message}</span> : null}
          {bindings?.state === 'ready' ? (
            originRelations.length ? (
              <select value={draft.origin_binding_id} aria-invalid={errors.origin_binding_id ? true : undefined} aria-describedby="pv-binding-help" onChange={(event) => chooseBinding(event.target.value)}>
                <option value="">Choose an origin relation</option>
                {originRelations.map((item) => <option key={str(item, 'id')} value={str(item, 'id')}>{str(item, 'origin_target_id')} ({str(item, 'id')})</option>)}
              </select>
            ) : <span className="td-muted small">No active origin relation is declared for this target. Declare one under Origin relations first; its ownership proofs authorize origin checks.</span>
          ) : null}
          <span id="pv-binding-help" className={errors.origin_binding_id ? 'td-form-error' : 'td-muted small'}>{errors.origin_binding_id ?? 'Origin paths reuse the relation’s recorded host, SNI, port and path. Nothing new is authorized here.'}</span>
        </label>
      ) : null}

      {kind && kind !== 'primary_route' && kind !== 'origin' ? (
        <div data-pv-field="entry_target_id">
          <TargetCandidatePicker
            config={config}
            session={session}
            legend="Entry target"
            value={draft.entry_target_id}
            excludeIds={[targetId]}
            error={errors.entry_target_id}
            help="Choose an existing declared target. Checks on it need its own ownership proof."
            onChange={(id, candidate: TargetCandidate | null) => { setDraft((current) => ({ ...current, entry_target_id: id })); setEntryLabel(candidate?.value || id); }}
          />
          {draft.entry_target_id ? <p className="td-muted small">Selected: <span className="mono pv-break">{entryLabel || draft.entry_target_id}</span></p> : null}
        </div>
      ) : null}

      <label className="td-field" data-pv-field="expected_behavior">
        <span>Expected behavior</span>
        <select value={draft.expected_behavior} aria-invalid={errors.expected_behavior ? true : undefined} aria-describedby="pv-behavior-help" onChange={(event) => update({ expected_behavior: event.target.value })}>
          <option value="">Choose the expected behavior</option>
          {Object.entries(EXPECTED_BEHAVIOR_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <span id="pv-behavior-help" className={errors.expected_behavior ? 'td-form-error' : 'td-muted small'}>{errors.expected_behavior ?? 'Your declaration; it is never inferred from tags, logos or vendor names.'}</span>
      </label>

      <fieldset data-pv-field="required_layers" aria-describedby="pv-layers-help" aria-invalid={errors.required_layers ? true : undefined} disabled={layersDisabled}>
        <legend>Required layers</legend>
        <div className="pv-grid-2">
          {PROTECTION_LAYERS.map((layer) => (
            <label key={layer} className="pv-check">
              <input type="checkbox" checked={draft.required_layers.includes(layer)} onChange={(event) => toggleLayer(layer, event.target.checked)} />
              {LAYER_LABELS[layer]}
            </label>
          ))}
        </div>
        <span id="pv-layers-help" className={errors.required_layers ? 'td-form-error' : 'td-muted small'}>{errors.required_layers ?? (layersDisabled ? 'An intentionally public path has no required layers.' : 'Each layer is evaluated separately. A WAF result never proves DDoS capacity or firewall traversal.')}</span>
      </fieldset>

      <div className="pv-grid-2">
        <label className="td-field" data-pv-field="owner">
          <span>Owner</span>
          <input value={draft.owner} maxLength={120} aria-invalid={errors.owner ? true : undefined} aria-describedby="pv-owner-help" onChange={(event) => update({ owner: event.target.value })} />
          <span id="pv-owner-help" className={errors.owner ? 'td-form-error' : 'td-muted small'}>{errors.owner ?? 'Team or person accountable for this path.'}</span>
        </label>
      </div>
      <label className="td-field" data-pv-field="purpose">
        <span>Purpose</span>
        <textarea value={draft.purpose} maxLength={500} aria-invalid={errors.purpose ? true : undefined} aria-describedby="pv-purpose-help" onChange={(event) => update({ purpose: event.target.value })} />
        <span id="pv-purpose-help" className={errors.purpose ? 'td-form-error' : 'td-muted small'}>{errors.purpose ?? 'Why this path exists, for example a partner integration hostname.'}</span>
      </label>

      <div className="row-actions">
        <Button type="submit" size="sm">Review declaration</Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}
