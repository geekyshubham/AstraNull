import { useEffect, useMemo, useState } from 'react';
import { Plus } from 'lucide-react';
import {
  originBindingCandidates,
  originBindingErrorCode,
  originBindingErrorMessage,
  originBindingRole,
  originBindingScope,
} from '../../lib/domain-checks.mjs';
import { archiveOriginBinding, createOriginBinding, fetchTargetOriginBindings, type OriginBindingList } from '../../lib/target-detail-api';
import { requestJson } from '../../lib/api';
import { ConfirmModal } from '../../lib/crud-ui';
import { buildDetailHref } from '../../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : '';
}

function rec(value: unknown): DataItem | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as DataItem : null;
}

function scopeText(binding: DataItem) {
  const port = str(binding, 'port');
  const path = str(binding, 'path');
  return `Host ${str(binding, 'host') || 'not recorded'} · SNI ${str(binding, 'sni') || 'not recorded'} · port ${port || 'from the declaration default'} · path ${path || '/'}`;
}

const REACH_LABEL: Record<string, string> = {
  reachable: 'Origin answered directly',
  unreachable: 'Origin did not answer directly',
  pass: 'Origin check passed',
  fail: 'Origin check found a gap',
};

const REACH_REASON: Record<string, string> = {
  no_bound_finalized_evidence: 'No finished origin check has run under this relation yet.',
  authorization_lapsed: 'Origin ownership is no longer verified, so earlier results are not shown as current.',
  no_active_binding: 'This relation is not active.',
  bound_origin_evidence_is_on_origin_target: 'Results under this relation are recorded on the origin target.',
};

type Review =
  | { kind: 'create'; origin: { id: string; value: string }; scope: { port?: number; path?: string } }
  | { kind: 'archive'; binding: DataItem }
  | { kind: 'check'; binding: DataItem; check: DataItem };

/**
 * Declared origin relations for one target. A hostname (or non-IP URL) target declares which of
 * its verified origin targets serves it; an origin IP target shows the relations that name it and
 * can start the approved origin check under one exact relation. Only existing declared targets are
 * offered; nothing is discovered, and a relation is never presented as an origin lockdown.
 */
export function OriginRelations({
  config,
  session,
  target,
  profile,
  canWrite,
  canStart,
  ownershipDone,
  onStarted,
  onChanged,
}: {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  profile: DataItem | null;
  canWrite: boolean;
  canStart: boolean;
  ownershipDone: boolean;
  onStarted: (message: string, runId: string) => void;
  /** Re-read the target profile after a relation write, so reachability reflects the current relations. */
  onChanged: () => void;
}) {
  const targetId = str(target, 'id');
  const role = originBindingRole(target);
  const [list, setList] = useState<OriginBindingList | null>(null);
  const [reload, setReload] = useState(0);
  const [formOpen, setFormOpen] = useState(false);
  const [originId, setOriginId] = useState('');
  const [port, setPort] = useState('');
  const [path, setPath] = useState('');
  const [formErrors, setFormErrors] = useState<{ origin?: string; port?: string; path?: string }>({});
  const [review, setReview] = useState<Review | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!role) return undefined;
    const controller = new AbortController();
    setList(null);
    fetchTargetOriginBindings(config, session, targetId, controller.signal).then((result) => {
      if (!controller.signal.aborted) setList(result);
    });
    return () => controller.abort();
  }, [config, session, targetId, role, reload]);

  const [inventory, setInventory] = useState<{ items: DataItem[]; truncated: boolean; error: string } | null>(null);

  useEffect(() => {
    if (role !== 'protected') return undefined;
    const controller = new AbortController();
    loadOriginInventory(config, session, controller.signal).then((result) => {
      if (!controller.signal.aborted) setInventory(result);
    });
    return () => controller.abort();
  }, [config, session, role, reload]);

  const profileBindings = useMemo(() => {
    const rows = Array.isArray(profile?.origin_bindings) ? profile!.origin_bindings as unknown[] : [];
    return new Map(rows.map(rec).filter((row): row is DataItem => row !== null).map((row) => [str(row, 'id'), row]));
  }, [profile]);

  const bindings: DataItem[] = useMemo(() => {
    const source = list?.state === 'ready' ? list.items : [...profileBindings.values()];
    return source
      .filter((binding) => (role === 'protected' ? str(binding, 'protected_target_id') : str(binding, 'origin_target_id')) === targetId)
      .map((binding): DataItem => ({ ...binding, reachability: rec(profileBindings.get(str(binding, 'id'))?.reachability) ?? rec(binding.reachability) }));
  }, [list, profileBindings, role, targetId]);

  const candidates = useMemo(() => originBindingCandidates(inventory?.items ?? [], target), [inventory, target]);
  const inventoryById = useMemo(() => new Map((inventory?.items ?? []).map((item) => [str(item, 'id'), item])), [inventory]);
  const [approved, setApproved] = useState<ApprovedOriginChecks>({ state: 'loading' });
  const [approvedReload, setApprovedReload] = useState(0);

  // The global catalog list leaves out checks that need setup input, so the approved origin checks
  // come from this target's own compatible pairs and each exact catalog definition.
  useEffect(() => {
    if (role !== 'origin' || !canStart) return undefined;
    const controller = new AbortController();
    setApproved({ state: 'loading' });
    loadApprovedOriginChecks(config, session, targetId, controller.signal).then((result) => {
      if (!controller.signal.aborted) setApproved(result);
    });
    return () => controller.abort();
  }, [config, session, targetId, role, canStart, approvedReload]);

  const originChecks = approved.state === 'ready' ? approved.items : [];
  const [checkChoice, setCheckChoice] = useState<Record<string, string>>({});

  if (!role) return null;

  const manageable = list?.state === 'ready';
  const active = bindings.filter((binding) => str(binding, 'status') === 'active');
  const archived = bindings.filter((binding) => str(binding, 'status') !== 'active');

  function openReview() {
    const errors: { origin?: string; port?: string; path?: string } = {};
    const origin = candidates.ready.find((candidate) => candidate.id === originId);
    if (!origin) errors.origin = 'Choose a verified origin target.';
    const scope = originBindingScope({ port, path });
    Object.assign(errors, scope.errors);
    setFormErrors(errors);
    if (!origin || !scope.valid) return;
    setError('');
    setReview({ kind: 'create', origin: { id: origin.id, value: origin.value }, scope: scope.scope });
  }

  async function confirm() {
    if (!review) return;
    setBusy(true);
    setError('');
    try {
      if (review.kind === 'create') {
        const created = await createOriginBinding(config, session, { protected_target_id: targetId, origin_target_id: review.origin.id, scope: review.scope });
        setMessage(created.replayed ? 'This relation was already recorded; nothing changed.' : 'Origin relation recorded. It is a declared relation, not a lockdown result.');
        setFormOpen(false);
        setOriginId('');
        setPort('');
        setPath('');
      } else if (review.kind === 'archive') {
        await archiveOriginBinding(config, session, str(review.binding, 'id'));
        setMessage('Origin relation archived. Earlier results stay in history.');
      } else {
        const run = await requestJson(config, session, '/v1/test-runs', {
          method: 'POST',
          body: {
            check_id: checkIdOf(review.check),
            target_group_id: str(target, 'target_group_id'),
            target_id: targetId,
            origin_binding_id: str(review.binding, 'id'),
          },
        }) as DataItem;
        onStarted('Origin check started under this relation. Its result appears in history once it is finalized.', str(run, 'id'));
      }
      if (review.kind !== 'check') onChanged();
      setReview(null);
      setReload((value) => value + 1);
    } catch (err) {
      setError(originBindingErrorMessage(err));
      // A scope conflict needs a different choice, so return to the kept form; nothing was replaced.
      if (review.kind === 'create' && originBindingErrorCode(err) === 'scope_conflict') setReview(null);
    } finally {
      setBusy(false);
    }
  }

  const checkBound = review?.kind === 'check' ? Number(rec(review.check.probe_profile)?.max_requests) : NaN;
  const checkIdOf = (check: DataItem) => str(check, 'check_id') || str(check, 'id');

  return (
    <section className="td-origin-relations" aria-labelledby="td-origin-relations-title">
      <header className="td-section-head">
        <div>
          <h2 id="td-origin-relations-title">Origin relations</h2>
          <p>
            {role === 'protected'
              ? 'Which of your verified origin targets serves this hostname. A relation fixes the exact scope an origin check may use. It does not test anything and is not an origin lockdown.'
              : 'Hostnames that declare this address as their origin. An origin check runs only under one of these relations, with its recorded host, SNI, port and path.'}
          </p>
        </div>
        {role === 'protected' && canWrite && manageable && !formOpen ? (
          <Button size="sm" variant="secondary" onClick={() => { setFormOpen(true); setMessage(''); setError(''); }}><Plus size={14} aria-hidden="true" />Declare origin relation</Button>
        ) : null}
      </header>

      {message ? <p className="form-banner" role="status">{message}</p> : null}
      {error && !review ? <p className="td-form-error" role="alert">{error}</p> : null}
      {list === null ? <div className="skeleton skeleton-row" aria-label="Loading origin relations" /> : null}
      {list?.state === 'unsupported' ? <p className="td-muted">Managing relations is not available from this server yet. Active relations from the target profile are shown read-only.</p> : null}
      {list?.state === 'unavailable' ? (
        <p className="td-form-error" role="alert">{list.code === 'forbidden' ? 'Your role cannot read origin relations.' : list.message} <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}>Retry</Button></p>
      ) : null}

      {formOpen ? (
        <form className="td-declaration-form td-origin-form" onSubmit={(event) => { event.preventDefault(); openReview(); }} noValidate>
          <h3>Declare an origin relation</h3>
          {inventory === null ? <div className="skeleton skeleton-row" aria-label="Loading declared origin targets" /> : null}
          {inventory?.error ? <p className="td-form-error" role="alert">{inventory.error}</p> : null}
          {inventory?.truncated ? <p className="td-muted small">Only the first {inventory.items.length} declared IP and URL targets were read. If your origin is missing, narrow your inventory first.</p> : null}
          {inventory === null || inventory.error ? null : candidates.ready.length ? (
            <label className="td-field">
              <span>Origin target</span>
              <select value={originId} aria-invalid={formErrors.origin ? true : undefined} aria-describedby="td-origin-choice-help" onChange={(event) => setOriginId(event.target.value)}>
                <option value="">Choose a verified origin target</option>
                {candidates.ready.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.value} ({candidate.id})</option>)}
              </select>
              <span id="td-origin-choice-help" className={formErrors.origin ? 'td-form-error' : 'td-muted'}>{formErrors.origin ?? 'Only declared IP targets with verified ownership are listed.'}</span>
            </label>
          ) : (
            <p className="td-muted">No declared origin target has verified ownership. Add the origin IP as a target and prove ownership first. <a href="#targets">Go to targets</a></p>
          )}
          {candidates.blocked.length ? (
            <p className="td-muted small">Not available until ownership is verified: {candidates.blocked.map((candidate) => `${candidate.value} (${candidate.id})`).join(', ')}.</p>
          ) : null}
          <div className="td-origin-scope">
            <label className="td-field">
              <span>Port (optional)</span>
              <input inputMode="numeric" value={port} aria-invalid={formErrors.port ? true : undefined} aria-describedby="td-origin-port-help" onChange={(event) => setPort(event.target.value)} />
              <span id="td-origin-port-help" className={formErrors.port ? 'td-form-error' : 'td-muted'}>{formErrors.port ?? 'Only when this target declares several ports.'}</span>
            </label>
            <label className="td-field">
              <span>Path (optional)</span>
              <input value={path} aria-invalid={formErrors.path ? true : undefined} aria-describedby="td-origin-path-help" onChange={(event) => setPath(event.target.value)} />
              <span id="td-origin-path-help" className={formErrors.path ? 'td-form-error' : 'td-muted'}>{formErrors.path ?? 'Only when this target declares several paths.'}</span>
            </label>
          </div>
          <div className="row-actions">
            <Button type="submit" size="sm" disabled={!candidates.ready.length}>Review relation</Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => { setFormOpen(false); setFormErrors({}); }}>Cancel</Button>
          </div>
        </form>
      ) : null}

      {list !== null ? (
        active.length ? (
          <ul className="td-origin-list">
            {active.map((binding) => {
              const otherId = role === 'protected' ? str(binding, 'origin_target_id') : str(binding, 'protected_target_id');
              const otherValue = role === 'protected' ? str(inventoryById.get(otherId), 'value') : str(binding, 'host');
              const reach = rec(binding.reachability);
              const reachStatus = str(reach, 'status');
              const observed = reach && str(reach, 'observation_id') && REACH_LABEL[reachStatus];
              const authorized = binding.currently_authorized === true;
              const bindingId = str(binding, 'id');
              const chosenId = checkChoice[bindingId] ?? (originChecks.length === 1 ? checkIdOf(originChecks[0]) : '');
              const chosenCheck = originChecks.find((check) => checkIdOf(check) === chosenId) ?? null;
              const checkDisabledReason = !canStart ? 'Your role cannot start checks.'
                : !authorized ? 'Origin ownership is not currently verified.'
                  : !ownershipDone ? 'Prove ownership of this target first.'
                    : approved.state === 'loading' ? 'Loading the approved origin checks for this target.'
                      : approved.state === 'error' ? `Approved origin checks could not load: ${approved.message}`
                        : !originChecks.length ? 'No approved origin check is available for this target.'
                          : !chosenCheck ? 'Choose an approved origin check.' : '';
              return (
                <li key={str(binding, 'id')} className="td-origin-item">
                  <div className="td-origin-pair">
                    <span className="td-label">{role === 'protected' ? 'Origin' : 'Serves hostname'}</span>
                    <a className="mono" href={buildDetailHref('target-detail', otherId)}>{otherValue || otherId}</a>
                    <span className="td-muted small mono">{otherId}</span>
                  </div>
                  <p className="td-muted small">{scopeText(binding)}</p>
                  <div className="td-origin-badges">
                    <Badge tone={authorized ? 'default' : 'warn'}>{authorized ? 'Ownership current' : 'Ownership not current'}</Badge>
                    <Badge tone="muted">Declared relation, no lockdown claim</Badge>
                  </div>
                  <p className="small">
                    {observed
                      ? <>{REACH_LABEL[reachStatus]} under this relation (recorded observation <span className="mono">{str(reach, 'observation_id')}</span>). This is a reachability result for this scope only, not an origin lockdown or capacity assurance.</>
                      : REACH_REASON[str(reach, 'reason') || (role === 'protected' ? 'bound_origin_evidence_is_on_origin_target' : 'no_bound_finalized_evidence')] ?? REACH_REASON.no_bound_finalized_evidence}
                  </p>
                  {binding.created_at ? <p className="td-muted small">Recorded {formatDate(binding.created_at)}</p> : null}
                  <div className="row-actions">
                    {role === 'origin' && canStart && authorized && originChecks.length > 1 ? (
                      <label className="td-field td-origin-check-choice">
                        <span>Approved origin check</span>
                        <select value={chosenId} onChange={(event) => setCheckChoice((current) => ({ ...current, [bindingId]: event.target.value }))}>
                          <option value="">Choose a check</option>
                          {originChecks.map((check) => <option key={checkIdOf(check)} value={checkIdOf(check)}>{str(check, 'name') || checkIdOf(check)}</option>)}
                        </select>
                      </label>
                    ) : null}
                    {role === 'origin' ? (
                      <Button size="sm" variant="secondary" disabled={Boolean(checkDisabledReason)} title={checkDisabledReason || undefined} onClick={() => chosenCheck && setReview({ kind: 'check', binding, check: chosenCheck })}>
                        Review origin check
                      </Button>
                    ) : null}
                    {canWrite && manageable ? (
                      <Button size="sm" variant="ghost" onClick={() => setReview({ kind: 'archive', binding })}>Archive relation</Button>
                    ) : null}
                    {role === 'origin' && checkDisabledReason ? <span className="td-muted small">{checkDisabledReason}</span> : null}
                    {role === 'origin' && canStart && approved.state === 'error' ? (
                      <Button size="sm" variant="ghost" onClick={() => setApprovedReload((value) => value + 1)}>Retry loading checks</Button>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="td-muted">
            {role === 'protected' ? 'No origin relation is declared for this hostname.' : 'No hostname declares this address as its origin.'}
            {role === 'origin' ? <> Declare it from the hostname target.</> : null}
          </p>
        )
      ) : null}
      {archived.length ? <p className="td-muted small">{archived.length} archived relation{archived.length === 1 ? '' : 's'} kept for history.</p> : null}

      <ConfirmModal
        open={review !== null}
        title={review?.kind === 'create' ? 'Record this origin relation?' : review?.kind === 'archive' ? 'Archive this origin relation?' : 'Start the origin check under this relation?'}
        confirmTone={review?.kind === 'archive' ? 'danger' : 'default'}
        confirmLabel={review?.kind === 'create' ? 'Record relation' : review?.kind === 'archive' ? 'Archive relation' : 'Start origin check'}
        busy={busy}
        onCancel={() => { setReview(null); setError(''); }}
        onConfirm={() => void confirm()}
        description={(
          <div className="stack-tight scan-review">
            {review?.kind === 'create' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Protected hostname</dt><dd><span className="mono">{str(target, 'value')}</span> <span className="mono td-muted">{targetId}</span></dd></div>
                  <div><dt>Origin target</dt><dd><span className="mono">{review.origin.value}</span> <span className="mono td-muted">{review.origin.id}</span></dd></div>
                  <div><dt>Host and SNI</dt><dd>From this target&apos;s declaration</dd></div>
                  <div><dt>Port</dt><dd>{review.scope.port ?? 'From the declaration'}</dd></div>
                  <div><dt>Path</dt><dd>{review.scope.path ?? 'From the declaration'}</dd></div>
                </dl>
                <p>This records a declared relation and is audited. It sends no traffic and does not claim the origin is locked down. The server re-checks origin ownership now.</p>
              </>
            ) : null}
            {review?.kind === 'archive' ? (
              <>
                <p className="mono">{scopeText(review.binding)}</p>
                <p>Archiving stops new origin checks under this relation. Results already recorded stay in history.</p>
              </>
            ) : null}
            {review?.kind === 'check' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Relation</dt><dd className="mono">{str(review.binding, 'id')}</dd></div>
                  <div><dt>Origin target</dt><dd><span className="mono">{str(target, 'value')}</span> <span className="mono td-muted">{targetId}</span></dd></div>
                  <div><dt>Scope</dt><dd className="mono">{scopeText(review.binding)}</dd></div>
                  <div><dt>Check</dt><dd>{str(review.check, 'name') || str(review.check, 'check_id')} <span className="mono td-muted">{str(review.check, 'check_id')}</span></dd></div>
                  <div><dt>Upper bound</dt><dd>{Number.isFinite(checkBound) ? `${checkBound} requests` : 'Not recorded in the catalog'}</dd></div>
                </dl>
                <p>The check uses only the relation&apos;s recorded host, SNI, port and path. The server re-checks both ownership proofs, safe windows and rate limits now. A result shows reachability for this scope only.</p>
              </>
            ) : null}
            {error && review ? <p className="td-form-error" role="alert">{error}</p> : null}
          </div>
        )}
      />
    </section>
  );
}

type ApprovedOriginChecks = { state: 'loading' } | { state: 'ready'; items: DataItem[] } | { state: 'error'; message: string };

const CHECK_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

/**
 * Approved origin checks for one origin target: the `setup_required` pairs from
 * `GET /v1/targets/:id/compatible-checks`, each read in full from `GET /v1/checks/:id` and kept
 * only when its probe profile is the host/SNI origin kind the server accepts under a relation.
 */
async function loadApprovedOriginChecks(config: PortalConfig, session: Session, targetId: string, signal: AbortSignal): Promise<ApprovedOriginChecks> {
  try {
    const payload = rec(await requestJson(config, session, `/v1/targets/${encodeURIComponent(targetId)}/compatible-checks`, { signal }));
    const pairs = Array.isArray(payload?.checks) ? payload!.checks as unknown[] : Array.isArray(rec(payload?.coverage)?.pairs) ? rec(payload?.coverage)!.pairs as unknown[] : [];
    const ids = [...new Set(pairs.map(rec)
      .filter((pair): pair is DataItem => pair !== null && (str(pair, 'exclusion_reason') === 'setup_required' || str(pair, 'pair_reason') === 'setup_required'))
      .map((pair) => str(pair, 'check_id'))
      .filter((id) => CHECK_ID_PATTERN.test(id)))];
    const definitions = await Promise.all(ids.map((id) => requestJson(config, session, `/v1/checks/${encodeURIComponent(id)}`, { signal })
      .then((body) => rec(rec(body)?.check))));
    const items = definitions.filter((check): check is DataItem => check !== null && str(rec(check.probe_profile), 'kind') === 'host_sni_bypass');
    return { state: 'ready', items };
  } catch (err) {
    return { state: 'error', message: err instanceof Error ? err.message : 'Approved origin checks could not load.' };
  }
}

const ORIGIN_KINDS = ['ip', 'url'] as const;
const INVENTORY_PAGE_LIMIT = 200;
const INVENTORY_MAX_PAGES = 5;

/**
 * Declared IP and URL targets read through the server's own `kind` filter, newest pages first, so
 * candidates are always existing declarations. Reading stops after a fixed number of pages and
 * says so instead of implying completeness.
 */
async function loadOriginInventory(config: PortalConfig, session: Session, signal: AbortSignal) {
  const items: DataItem[] = [];
  let truncated = false;
  try {
    for (const kind of ORIGIN_KINDS) {
      let cursor = '';
      for (let page = 0; page < INVENTORY_MAX_PAGES; page += 1) {
        const params = new URLSearchParams({ kind, limit: String(INVENTORY_PAGE_LIMIT) });
        if (cursor) params.set('cursor', cursor);
        const payload = await requestJson(config, session, `/v1/targets?${params.toString()}`, { signal }) as DataItem;
        const pageBlock = rec(payload.page);
        const rows = Array.isArray(pageBlock?.items) ? pageBlock!.items as DataItem[] : Array.isArray(payload.items) ? payload.items as DataItem[] : [];
        items.push(...rows);
        cursor = str(pageBlock, 'next_cursor') || str(payload, 'next_cursor');
        if (!cursor) break;
        if (page === INVENTORY_MAX_PAGES - 1) truncated = true;
      }
    }
    return { items, truncated, error: '' };
  } catch (err) {
    return { items, truncated, error: err instanceof Error ? `Declared origin targets could not load: ${err.message}` : 'Declared origin targets could not load.' };
  }
}
