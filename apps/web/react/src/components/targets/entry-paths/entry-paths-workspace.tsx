import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Plus } from 'lucide-react';
import {
  archiveEntryPath,
  createEntryPath,
  getProtectionMatrix,
  listEntryPaths,
  pvErrorCode,
  type EntryPath,
  type ProtectionMatrix,
  type PvFailure,
} from '../../../lib/protection-validation-api';
import { ConfirmModal } from '../../../lib/crud-ui';
import { apiErrorMessage } from '../../../lib/error-messages';
import { buildDetailHref } from '../../../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../../../lib/types';
import { formatDate } from '../../../lib/utils';
import { Badge } from '../../ui/badge';
import { Button } from '../../ui/button';
import { EntryPathForm, type EntryPathReview } from './entry-path-form';
import { PathComparisonPanel } from './path-comparison';
import {
  authorizationView,
  EXPECTED_BEHAVIOR_LABELS,
  LAYER_LABELS,
  labelFrom,
  RELATION_KIND_LABELS,
  splitEntryPathsByAnchor,
  writeErrorCopy,
} from './presenter.mjs';
import { ProtectionMatrixTable } from './protection-matrix';
import { FailureNotice, useStickySelection } from './shared';
import './entry-paths.css';

type PathsState = { state: 'loading' } | { state: 'ready'; items: EntryPath[]; nextCursor: string; loadingMore: boolean; moreError: string } | { state: 'failed'; failure: PvFailure };
type MatrixState = { state: 'loading' } | { state: 'ready'; value: ProtectionMatrix } | { state: 'failed'; failure: PvFailure };
type Review = { kind: 'create'; review: EntryPathReview } | { kind: 'archive'; path: EntryPath };

function str(item: DataItem | null | undefined, key: string) {
  const value = item?.[key];
  return typeof value === 'string' ? value : '';
}

function layerList(layers: string[]) {
  return layers.length ? layers.map((layer) => labelFrom(LAYER_LABELS, layer)).join(', ') : 'None';
}

/** Declared application entry paths, their per-layer evidence, and reviewed comparisons for one anchor target. */
export function DeclaredEntryPaths({
  config,
  session,
  target,
  canWrite,
  canStart,
  ownershipDone,
  onStarted,
}: {
  config: PortalConfig;
  session: Session;
  target: DataItem;
  canWrite: boolean;
  canStart: boolean;
  ownershipDone: boolean;
  onStarted: (message: string) => void;
}) {
  const targetId = str(target, 'id');
  const [paths, setPaths] = useState<PathsState>({ state: 'loading' });
  const [matrix, setMatrix] = useState<MatrixState>({ state: 'loading' });
  const listController = useRef<AbortController | null>(null);
  const [reload, setReload] = useState(0);
  const [formOpen, setFormOpen] = useState(false);
  const [review, setReview] = useState<Review | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [showArchived, setShowArchived] = useState(false);
  const [selectedPathId, setSelectedPathId] = useStickySelection(session, targetId, 'matrix-path');
  const [selectedLayer, setSelectedLayer] = useStickySelection(session, targetId, 'matrix-layer');

  useEffect(() => {
    const controller = new AbortController();
    listController.current = controller;
    listEntryPaths(config, session, targetId, {}, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setPaths(result.state === 'ready' ? { state: 'ready', items: result.value.items, nextCursor: result.value.nextCursor, loadingMore: false, moreError: '' } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    getProtectionMatrix(config, session, targetId, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setMatrix(result.state === 'ready' ? { state: 'ready', value: result.value } : { state: 'failed', failure: result });
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [config, session, targetId, reload]);

  const loadMore = useCallback(async () => {
    const controller = listController.current;
    if (paths.state !== 'ready' || paths.loadingMore || !paths.nextCursor || !controller || controller.signal.aborted) return;
    setPaths({ ...paths, loadingMore: true, moreError: '' });
    const result = await listEntryPaths(config, session, targetId, { cursor: paths.nextCursor }, controller.signal);
    if (controller.signal.aborted) return;
    setPaths((current) => {
      if (current.state !== 'ready') return current;
      if (result.state !== 'ready') return { ...current, loadingMore: false, moreError: 'More entry paths could not load. Retry.' };
      const seen = new Set(current.items.map((item) => item.id));
      return { ...current, items: [...current.items, ...result.value.items.filter((item) => !seen.has(item.id))], nextCursor: result.value.nextCursor, loadingMore: false };
    });
  }, [config, session, targetId, paths]);

  const { anchored, referenced } = useMemo(() => splitEntryPathsByAnchor(paths.state === 'ready' ? paths.items : [], targetId), [paths, targetId]);
  const active = anchored.filter((path) => path.status === 'active');
  const archived = anchored.filter((path) => path.status !== 'active');
  const referencedActive = referenced.filter((path) => path.status === 'active');
  const unsupported = paths.state === 'failed' && (paths.failure.state === 'unsupported' || paths.failure.state === 'disabled');
  const sameFailure = paths.state === 'failed' && matrix.state === 'failed' && paths.failure.state === matrix.failure.state;
  const manageable = paths.state === 'ready';

  useEffect(() => {
    if (matrix.state !== 'ready' || !selectedPathId) return;
    if (!matrix.value.paths.some((path) => path.entry_path_id === selectedPathId)) {
      setSelectedPathId('');
      setSelectedLayer('');
    }
  }, [matrix, selectedPathId, setSelectedPathId, setSelectedLayer]);

  async function confirm() {
    if (!review) return;
    setBusy(true);
    setError('');
    try {
      if (review.kind === 'create') {
        const written = await createEntryPath(config, session, targetId, review.review.body);
        setMessage(written.replayed ? 'This entry path was already declared; nothing changed.' : 'Entry path declared and audited. No traffic was sent.');
        setFormOpen(false);
      } else {
        await archiveEntryPath(config, session, review.path.id);
        setMessage('Entry path archived. It can no longer authorize checks; earlier results stay in history.');
      }
      setReview(null);
      setReload((value) => value + 1);
    } catch (err) {
      setError(writeErrorCopy(pvErrorCode(err), apiErrorMessage(err, 'The change could not be saved. Nothing was changed.')));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="pv-section td-entry-paths" aria-labelledby="pv-entry-paths-title">
      <header className="td-section-head">
        <div>
          <h2 id="pv-entry-paths-title">Declared entry paths</h2>
          <p>Every route into the application anchored on this target: alternate hostnames, service and login URLs, origins and fallback routes. Each layer is evaluated separately from external evidence; no connector or vendor access is needed.</p>
        </div>
        {canWrite && manageable && !formOpen ? (
          <Button size="sm" variant="secondary" onClick={() => { setFormOpen(true); setMessage(''); setError(''); }}><Plus size={14} aria-hidden="true" />Declare entry path</Button>
        ) : null}
      </header>

      {!ownershipDone ? (
        <p className="pv-notice" data-tone="warn" data-state="unverified-target">This target&apos;s ownership is not verified. You can declare and inspect paths, but checks from this application are skipped until ownership is verified.</p>
      ) : null}
      {message ? <p className="form-banner" role="status">{message}</p> : null}
      {error && !review ? <p className="td-form-error" role="alert">{error}</p> : null}

      {formOpen ? (
        <EntryPathForm
          config={config}
          session={session}
          target={target}
          onCancel={() => setFormOpen(false)}
          onReview={(next) => { setError(''); setReview({ kind: 'create', review: next }); }}
        />
      ) : null}

      {paths.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading entry paths" /> : null}
      {paths.state === 'failed' ? <FailureNotice failure={paths.failure} subject="declared entry paths" onRetry={() => setReload((value) => value + 1)} /> : null}

      {paths.state === 'ready' ? (
        active.length ? (
          <ul className="pv-list" aria-label="Active entry paths">
            {active.map((path) => <EntryPathCard key={path.id} path={path} canArchive={canWrite} onArchive={() => { setError(''); setReview({ kind: 'archive', path }); }} />)}
          </ul>
        ) : (
          <div className="pv-notice" data-state="empty">
            <span>No entry path is declared for this application yet. Declare the primary route first, then each alternate hostname, service or login URL, origin or fallback route you want validated.</span>
          </div>
        )
      ) : null}
      {paths.state === 'ready' && paths.nextCursor ? (
        <div className="pv-actions">
          <Button size="sm" variant="ghost" loading={paths.loadingMore} loadingText="Loading more" onClick={() => void loadMore()}>Load more entry paths</Button>
          {paths.moreError ? <span className="td-form-error small" role="alert">{paths.moreError}</span> : null}
        </div>
      ) : null}
      {referencedActive.length ? (
        <div className="pv-section" data-state="referenced-paths">
          <h3 className="td-label">Referenced by other applications</h3>
          <p className="td-muted small">This target is an entry path of another application. Manage these relations from that application; they are not part of this application&apos;s comparisons.</p>
          <ul className="pv-list" aria-label="Entry paths anchored on other applications">
            {referencedActive.map((path) => <EntryPathCard key={path.id} path={path} canArchive={false} onArchive={() => undefined} anchorHref={buildDetailHref('target-detail', path.anchor_target_id)} />)}
          </ul>
        </div>
      ) : null}
      {archived.length ? (
        <div className="pv-section">
          <Button size="sm" variant="ghost" aria-expanded={showArchived} onClick={() => setShowArchived((value) => !value)}>
            {showArchived ? 'Hide archived paths' : `Show ${archived.length} archived path${archived.length === 1 ? '' : 's'}`}
          </Button>
          {showArchived ? <ul className="pv-list" aria-label="Archived entry paths">{archived.map((path) => <EntryPathCard key={path.id} path={path} canArchive={false} onArchive={() => undefined} />)}</ul> : null}
        </div>
      ) : null}

      {!unsupported && !sameFailure ? (
        <section className="pv-section" aria-labelledby="pv-matrix-title">
          <header className="td-section-head">
            <div>
              <h3 id="pv-matrix-title">Evidence per path and layer</h3>
              <p>Recorded external results only. A block or bypass is reported against the path, not attributed to an inner layer, unless evidence establishes it.</p>
            </div>
            <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}>Refresh</Button>
          </header>
          {matrix.state === 'loading' ? <div className="skeleton skeleton-row" aria-label="Loading path evidence" /> : null}
          {matrix.state === 'failed' ? <FailureNotice failure={matrix.failure} subject="path evidence" onRetry={() => setReload((value) => value + 1)} /> : null}
          {matrix.state === 'ready' && !matrix.value.paths.length ? <p className="td-muted">No path evidence yet. Declare paths, then plan a comparison to collect it.</p> : null}
          {matrix.state === 'ready' && matrix.value.paths.length ? (
            <ProtectionMatrixTable
              matrix={matrix.value}
              selectedPathId={selectedPathId}
              selectedLayer={selectedLayer}
              onSelect={(pathId, layer) => { setSelectedPathId(pathId); setSelectedLayer(layer); }}
            />
          ) : null}
        </section>
      ) : null}

      {paths.state === 'ready' ? (
        <PathComparisonPanel config={config} session={session} target={target} paths={anchored} canStart={canStart} ownershipDone={ownershipDone} onStarted={(text) => { onStarted(text); setReload((value) => value + 1); }} />
      ) : null}

      <ConfirmModal
        open={review !== null}
        title={review?.kind === 'create' ? 'Record this entry path?' : 'Archive this entry path?'}
        confirmTone={review?.kind === 'archive' ? 'danger' : 'default'}
        confirmLabel={review?.kind === 'create' ? 'Record entry path' : 'Archive entry path'}
        busy={busy}
        onCancel={() => { setReview(null); setError(''); }}
        onConfirm={() => void confirm()}
        description={(
          <div className="stack-tight scan-review">
            {review?.kind === 'create' ? (
              <>
                <dl className="td-review-list">
                  <div><dt>Application anchor</dt><dd><span className="mono pv-break">{str(target, 'value') || targetId}</span></dd></div>
                  <div><dt>Relation</dt><dd>{labelFrom(RELATION_KIND_LABELS, review.review.body.relation_kind)}</dd></div>
                  <div><dt>Entry target</dt><dd><span className="mono pv-break">{review.review.entryLabel}</span> <span className="mono td-muted pv-break">{review.review.body.entry_target_id}</span></dd></div>
                  {review.review.body.origin_binding_id ? <div><dt>Origin relation</dt><dd className="mono pv-break">{review.review.body.origin_binding_id}</dd></div> : null}
                  <div><dt>Expected behavior</dt><dd>{labelFrom(EXPECTED_BEHAVIOR_LABELS, review.review.body.expected_behavior)}</dd></div>
                  <div><dt>Required layers</dt><dd>{layerList(review.review.body.required_layers)}</dd></div>
                  <div><dt>Owner</dt><dd className="pv-break">{review.review.body.owner}</dd></div>
                  <div><dt>Purpose</dt><dd className="pv-break">{review.review.body.purpose}</dd></div>
                </dl>
                <p>This records your declaration and is audited. It sends no traffic and authorizes nothing new; checks still need each target&apos;s own ownership proof.</p>
              </>
            ) : null}
            {review?.kind === 'archive' ? (
              <p>Archiving <span className="mono pv-break">{review.path.entry_target_value || review.path.entry_target_id}</span> stops it from authorizing new checks. Recorded results and comparisons stay in history.</p>
            ) : null}
            {error && review ? <p className="td-form-error" role="alert">{error}</p> : null}
          </div>
        )}
      />
    </section>
  );
}

function EntryPathCard({ path, canArchive, onArchive, anchorHref }: { path: EntryPath; canArchive: boolean; onArchive: () => void; anchorHref?: string }) {
  const authorization = authorizationView(path);
  return (
    <li className="pv-card" data-entry-path-id={path.id}>
      <div className="pv-card-head">
        <div className="pv-card-title">
          <span className="td-label">{labelFrom(RELATION_KIND_LABELS, path.relation_kind)}</span>
          <a className="mono pv-break" href={buildDetailHref('target-detail', path.entry_target_id)}>{path.entry_target_value || path.entry_target_id}</a>
          <span className="td-muted small mono pv-break">{path.entry_target_id}{path.declaration_version ? ` · declaration v${path.declaration_version}` : ''}</span>
        </div>
        {canArchive && path.status === 'active' ? <Button size="sm" variant="ghost" onClick={onArchive}>Archive</Button> : null}
      </div>
      <div className="pv-badges">
        <Badge tone="muted">{labelFrom(EXPECTED_BEHAVIOR_LABELS, path.expected_behavior)}</Badge>
        {path.status === 'active' ? <Badge tone={authorization.tone}>{authorization.label}</Badge> : <Badge tone="muted">Archived</Badge>}
        <Badge tone="muted">Declared, not a protection result</Badge>
      </div>
      <p className="small">Required layers: {layerList(path.required_layers)}</p>
      {anchorHref ? <p className="td-muted small">Anchored on application <a className="mono pv-break" href={anchorHref}>{path.anchor_target_id}</a>.</p> : null}
      {path.origin_binding_id ? <p className="td-muted small">Uses origin relation <span className="mono pv-break">{path.origin_binding_id}</span> and its recorded host, SNI, port and path.</p> : null}
      <p className="td-muted small pv-break">{path.owner ? `Owner ${path.owner}. ` : ''}{path.purpose}</p>
      {path.created_at ? <p className="td-muted small">Declared {formatDate(path.created_at)}{path.archived_at ? ` · archived ${formatDate(path.archived_at)}` : ''}</p> : null}
    </li>
  );
}
