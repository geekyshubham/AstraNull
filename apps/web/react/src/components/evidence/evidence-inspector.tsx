import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { ChevronLeft, ChevronRight, CircleAlert, CircleDashed, Lock, RefreshCw, SearchX } from 'lucide-react';
import { requestJson, sessionIdentity } from '../../lib/api';
import {
  EVIDENCE_INSPECTOR_EVENT,
  classifyInspectorError,
  closeEvidenceInspector,
  createInspectorGeneration,
  evidenceContextPath,
  fallbackContextFromRecord,
  fallbackRecordPath,
  inspectorLoadKey,
  inspectorOriginFocusKey,
  inspectorRefKey,
  limitationLabel,
  normalizeEvidenceContext,
  parseInspectorRef,
  replaceEvidenceInspector,
  type EvidenceContextModel,
  type EvidenceInspectorRef,
  type InspectorObservation,
  type InspectorState,
} from '../../lib/evidence-inspector.mjs';
import { canAccessRoute } from '../../lib/route-access';
import { canStartRun } from '../../lib/run-permissions.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { plainCheckName, plainVerdictLabel } from '../../lib/plain-language.mjs';
import { providerName } from '../../lib/domain-checks.mjs';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { InspectorPanel } from '../ui/inspector-panel';
import { sequencePosition, useInspectorSequence } from './inspector-sequence';
import './evidence-inspector.css';

type Tone = 'success' | 'warn' | 'danger' | 'info' | 'muted' | 'default';

const ENTRY_TITLE: Record<EvidenceInspectorRef['entry'], string> = {
  finding: 'Finding evidence',
  group_member: 'Affected target evidence',
  check_result: 'Check result',
  provider: 'How this was identified',
  artifact: 'Evidence artifact',
  report: 'Report snapshot',
  audit: 'Audit event',
};

const FAMILY_LABEL: Record<string, string> = {
  waf: 'WAF',
  cdn: 'CDN',
  cloud: 'Edge or cloud layer',
  dns: 'DNS provider',
  origin_hosting: 'Origin hosting',
};

const FIELD_LABEL: Record<string, string> = {
  method: 'Method',
  path: 'Path',
  protocol: 'Protocol',
  engine: 'Engine',
  max_requests: 'Request upper bound',
  timeout_ms: 'Timeout (ms)',
  requests_sent: 'Requests sent',
  requests_simulated: 'Requests simulated',
  request_count: 'Request count',
  provenance: 'Provenance',
  status_code: 'Status code',
  external_result: 'External result',
  received_at: 'Received',
  provider: 'Provider',
  sources: 'Recorded sources',
  confidence: 'Recorded confidence',
  freshness: 'Freshness',
  rule_version: 'Rule version',
  reasons: 'Reasons',
};

const PASS = new Set(['pass', 'passed', 'protected', 'blocked', 'block_at_edge', 'allowed_as_expected']);
const FAIL = new Set(['fail', 'failed', 'gap', 'allowed', 'exposed', 'bypassable', 'penetrated', 'unprotected']);

/** Provider presence is attribution, never measured blocking, so it stays neutral. */
function providerTone(status: string): Tone {
  const key = status.toLowerCase();
  if (key === 'detected') return 'default';
  if (key === 'inconclusive' || key === 'attempt_failed' || key === 'error') return 'warn';
  return 'muted';
}

function outcomeTone(outcome: string): Tone {
  const key = outcome.toLowerCase();
  if (PASS.has(key)) return 'success';
  if (FAIL.has(key)) return 'danger';
  if (['inconclusive', 'unknown', 'not_recorded', 'not_checked'].includes(key)) return 'muted';
  return 'warn';
}

function humanize(value: string) {
  const label = value.replace(/_/g, ' ').trim();
  return label ? label.charAt(0).toUpperCase() + label.slice(1) : '';
}

function str(item: DataItem | null | undefined, keys: string[]) {
  for (const key of keys) {
    const value = item?.[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function NotRecorded({ children = 'Not recorded' }: { children?: ReactNode }) {
  return <span className="ei-not-recorded">{children}</span>;
}

function SummaryFields({ fields, empty }: { fields: Array<{ key: string; value: string }>; empty: string }) {
  if (!fields.length) return <NotRecorded>{empty}</NotRecorded>;
  return (
    <dl className="ei-kv">
      {fields.map((field) => (
        <div key={field.key}>
          <dt>{FIELD_LABEL[field.key] ?? humanize(field.key)}</dt>
          <dd className={/id$|path|engine|version/.test(field.key) ? 'mono' : undefined}>{field.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Integrity wording follows the recorded state; a digest or verification is never implied. */
function integrityText(integrity: NonNullable<InspectorObservation['integrity']>) {
  const status = integrity.status.toLowerCase();
  if (status === 'verified' && integrity.verifiedAt) return `Verified ${formatDate(integrity.verifiedAt)}${integrity.method ? ` (${integrity.method})` : ''}`;
  if (status === 'verified') return 'Reported verified, but no verification time is recorded. Treat as not verified.';
  if (status === 'failed' || status === 'verification_failed') return `Verification failed${integrity.verifiedAt ? ` ${formatDate(integrity.verifiedAt)}` : ''}.`;
  if (status === 'partial') return 'Some referenced records are verified and some are not; see each record.';
  if (status === 'recorded_digest') return 'Digest recorded. Not independently verified.';
  return 'No integrity record for these references.';
}

function ObservationBlock({ title, note, observation, missingIds = [] }: { title: string; note: string; observation: InspectorObservation; missingIds?: string[] }) {
  const integrity = observation.integrity;
  return (
    <section className="ei-observation" aria-label={title}>
      <header>
        <strong>{title}</strong>
        <span className="ei-note">{note}</span>
      </header>
      <dl className="ei-kv">
        <div><dt>Observed</dt><dd>{observation.observedAt ? formatDate(observation.observedAt) : <NotRecorded />}</dd></div>
        <div><dt>Recorded execution</dt><dd className="mono">{observation.testRunId || <NotRecorded />}</dd></div>
        {observation.verdictId ? <div><dt>Verdict record</dt><dd className="mono">{observation.verdictId}</dd></div> : null}
        <div>
          <dt>Evidence records</dt>
          <dd>
            {observation.evidenceIds.length ? (
              <ul className="ei-id-list">
                {observation.evidenceIds.map((id) => (
                  <li key={id}>
                    <a className="mono" href={`#evidence-detail?id=${encodeURIComponent(id)}`}>{id}</a>
                    {missingIds.includes(id) ? <span className="ei-note"> referenced, record not loadable</span> : null}
                  </li>
                ))}
              </ul>
            ) : <NotRecorded>No evidence reference recorded</NotRecorded>}
          </dd>
        </div>
        {integrity && observation.evidenceIds.length ? (
          <div>
            <dt>Integrity</dt>
            <dd>{integrityText(integrity)}</dd>
          </div>
        ) : null}
        {observation.closesFinding ? <div><dt>Lifecycle</dt><dd>Applied to this finding by the finding update path</dd></div> : null}
      </dl>
    </section>
  );
}

function StateNotice({ state, permission, onRetry, entry }: { state: InspectorState; permission: string; onRetry: () => void; entry: string }) {
  if (state === 'denied') {
    return (
      <div className="ei-state" data-state="denied" role="note">
        <Lock size={18} aria-hidden="true" />
        <div>
          <strong>Access required</strong>
          <p>Your role cannot read this {entry === 'audit' ? 'audit event' : 'evidence'}{permission ? ` (needs ${permission})` : ''}. Nothing was fetched through another route.</p>
        </div>
      </div>
    );
  }
  if (state === 'not_found') {
    return (
      <div className="ei-state" data-state="not_found" role="note">
        <SearchX size={18} aria-hidden="true" />
        <div>
          <strong>No longer available</strong>
          <p>This record was not found in your workspace. It may have been removed, or the link points at another workspace. No other record was substituted.</p>
        </div>
      </div>
    );
  }
  if (state === 'unbound') {
    return (
      <div className="ei-state" data-state="unbound" role="note">
        <CircleDashed size={18} aria-hidden="true" />
        <div>
          <strong>Relationship not recorded</strong>
          <p>The record exists but does not state which target and check it belongs to, so it is not shown as this result. Open it from its own target instead.</p>
        </div>
      </div>
    );
  }
  if (state === 'expired') {
    return (
      <div className="ei-state" data-state="expired" role="note">
        <CircleDashed size={18} aria-hidden="true" />
        <div><strong>Retention expired</strong><p>The source record passed its retention window. Its identity is kept; its content is not.</p></div>
      </div>
    );
  }
  if (state === 'no_refs') {
    const copy = entry === 'provider'
      ? { title: 'No observation recorded for this layer', body: 'Nothing has identified this layer on this target yet. It is shown as unknown, not as absent.' }
      : entry === 'report'
        ? { title: 'No snapshot references captured', body: 'This report did not record which results it used, so none are shown. Live results are not substituted.' }
        : { title: 'Supporting evidence not recorded for this result', body: 'The record exists, but it cites no evidence reference. Recorded fields are shown below.' };
    return (
      <div className="ei-state" data-state="no_refs" role="note">
        <CircleDashed size={18} aria-hidden="true" />
        <div><strong>{copy.title}</strong><p>{copy.body}</p></div>
      </div>
    );
  }
  if (state === 'unavailable') {
    return (
      <div className="ei-state" data-state="unavailable" role="alert">
        <CircleAlert size={18} aria-hidden="true" />
        <div>
          <strong>Evidence unavailable</strong>
          <p>The evidence read failed. This is not the same as having no evidence.</p>
          <Button size="sm" variant="secondary" onClick={onRetry}><RefreshCw size={14} aria-hidden="true" />Retry</Button>
        </div>
      </div>
    );
  }
  return null;
}

function nameForCheck(checks: DataItem[], checkId: string) {
  if (!checkId) return '';
  const check = checks.find((item) => str(item, ['check_id', 'id']) === checkId);
  return plainCheckName(str(check, ['name', 'title']) || checkId) as string;
}

function nameForTarget(targets: DataItem[], targetId: string, fallback = '') {
  if (!targetId) return fallback;
  const target = targets.find((item) => str(item, ['id']) === targetId);
  return str(target, ['value', 'name']) || fallback || targetId;
}

export type EvidenceInspectorHostProps = {
  config: PortalConfig;
  session: Session;
  data: PortalData;
  /** Changes whenever the shell route or path changes, so the host re-reads the address. */
  locationKey: string;
};

type LoadState = {
  key: string;
  model: EvidenceContextModel | null;
  state: InspectorState;
  permission: string;
  fallback: boolean;
};

/**
 * Root-mounted inspector. Reads the ID-only inspector parameters from the address on cold load,
 * Back/Forward and in-page opens, then issues read-only GETs. Never starts, exports, verifies,
 * or sends anything.
 */
export function EvidenceInspectorHost({ config, session, data, locationKey }: EvidenceInspectorHostProps) {
  const [ref, setRef] = useState<EvidenceInspectorRef | null>(() => parseInspectorRef(window.location.hash));
  const [reload, setReload] = useState(0);
  const [load, setLoad] = useState<LoadState>({ key: '', model: null, state: 'loading', permission: '', fallback: false });
  const generation = useRef(createInspectorGeneration());
  const sequence = useInspectorSequence();
  const focusKeyRef = useRef('');
  const scopeKey = sessionIdentity(session);
  const refKey = inspectorRefKey(ref);
  const loadKey = inspectorLoadKey(scopeKey, refKey);

  const syncFromLocation = useCallback(() => {
    const next = parseInspectorRef(window.location.hash);
    setRef((current) => (inspectorRefKey(current) === inspectorRefKey(next) ? current : next));
  }, []);

  useEffect(() => {
    syncFromLocation();
  }, [locationKey, syncFromLocation]);

  useEffect(() => {
    window.addEventListener('popstate', syncFromLocation);
    window.addEventListener('hashchange', syncFromLocation);
    window.addEventListener(EVIDENCE_INSPECTOR_EVENT, syncFromLocation);
    return () => {
      window.removeEventListener('popstate', syncFromLocation);
      window.removeEventListener('hashchange', syncFromLocation);
      window.removeEventListener(EVIDENCE_INSPECTOR_EVENT, syncFromLocation);
    };
  }, [syncFromLocation]);

  useEffect(() => {
    if (ref) {
      const key = inspectorOriginFocusKey();
      if (key) focusKeyRef.current = key;
    }
  }, [refKey, ref]);

  useEffect(() => {
    if (!ref) {
      generation.current.cancel();
      return undefined;
    }
    const token = generation.current.begin(scopeKey, refKey);
    const controller = new AbortController();
    setLoad({ key: loadKey, model: null, state: 'loading', permission: '', fallback: false });
    const current = () => generation.current.isCurrent(token);

    if (ref.entry === 'audit' && !canAccessRoute(session.role, 'audit', { principal: session.principal, staffRole: session.staff_role })) {
      setLoad({ key: loadKey, model: null, state: 'denied', permission: 'audit:read', fallback: false });
      return () => controller.abort();
    }

    async function resolve() {
      try {
        const payload = await requestJson(config, session, evidenceContextPath(ref!), { signal: controller.signal });
        if (!current()) return;
        const model = normalizeEvidenceContext(payload, ref);
        setLoad({ key: loadKey, model, state: model.state, permission: '', fallback: false });
      } catch (error) {
        if (!current() || controller.signal.aborted) return;
        const classified = classifyInspectorError(error);
        // Only a server without the context route falls back to an exact record read. Every other
        // failure keeps its own state: no permission, relationship or availability bypass.
        if (classified.state !== 'route_missing') {
          setLoad({ key: loadKey, model: null, state: classified.state, permission: classified.permission, fallback: false });
          return;
        }
        const recordPath = fallbackRecordPath(ref!);
        if (!recordPath) {
          setLoad({ key: loadKey, model: null, state: 'unavailable', permission: '', fallback: false });
          return;
        }
        try {
          const source = await requestJson(config, session, recordPath, { signal: controller.signal });
          if (!current()) return;
          const { payload, mismatch, unbound } = fallbackContextFromRecord(ref!, source);
          if (unbound) {
            setLoad({ key: loadKey, model: null, state: 'unbound', permission: '', fallback: true });
            return;
          }
          if (mismatch || !payload) {
            setLoad({ key: loadKey, model: null, state: 'not_found', permission: '', fallback: true });
            return;
          }
          const model = normalizeEvidenceContext(payload, ref);
          setLoad({ key: loadKey, model, state: model.state, permission: '', fallback: true });
        } catch (recordError) {
          if (!current() || controller.signal.aborted) return;
          const recordState = classifyInspectorError(recordError);
          setLoad({
            key: loadKey,
            model: null,
            state: recordState.state === 'route_missing' ? 'not_found' : recordState.state,
            permission: recordState.permission,
            fallback: true,
          });
        }
      }
    }
    void resolve();
    return () => controller.abort();
    // loadKey captures the ref identity and the tenant/user/role scope.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadKey, reload, config]);

  const restoreFocus = useCallback(() => {
    const key = focusKeyRef.current;
    if (!key) return null;
    const node = document.querySelector<HTMLElement>(`[data-focus-key="${CSS.escape(key)}"]`)
      ?? document.getElementById(key);
    if (!node) return null;
    return node.matches('a, button, input, select, textarea, [tabindex]') ? node : node.querySelector<HTMLElement>('a, button, [tabindex]') ?? node;
  }, []);

  const close = useCallback(() => {
    closeEvidenceInspector();
  }, []);

  const view = useMemo(() => {
    if (!ref) return null;
    // A committed model is readable only for the exact scope and ref it was read for.
    const model = load.key === loadKey ? load.model : null;
    const state: InspectorState = load.key === loadKey ? load.state : 'loading';
    const subject = model?.subject ?? {};
    const targetId = ref.target_id || subject.target_id || '';
    const checkId = ref.check_id || subject.check_id || '';
    const targetLabel = nameForTarget(data.targets, targetId, subject.target_value);
    const checkLabel = nameForCheck(data.checks, checkId);
    const findingId = ref.finding_id || subject.finding_id || '';
    const loadedFinding = findingId ? data.findings.find((item) => str(item, ['id']) === findingId) ?? null : null;
    const lifecycle = subject.lifecycle || str(loadedFinding, ['status', 'state']);
    return { model, state, targetId, checkId, targetLabel, checkLabel, subject: lifecycle ? { ...subject, lifecycle } : subject };
  }, [ref, loadKey, load, data.targets, data.checks, data.findings]);

  if (!ref || !view) return null;

  const { model, state, targetId, checkId, targetLabel, checkLabel, subject } = view;
  const position = sequencePosition(sequence, ref);
  const title = ref.entry === 'provider'
    ? `${ENTRY_TITLE.provider}: ${FAMILY_LABEL[ref.family ?? ''] ?? 'Provider'}`
    : ENTRY_TITLE[ref.entry];
  const answer = model?.answer ?? null;
  const outcome = answer?.outcome ?? '';
  const outcomeLabel = outcome
    ? ref.entry === 'provider' ? humanize(outcome) : plainVerdictLabel(outcome) || humanize(outcome)
    : '';
  const canRetest = canStartRun(session.role) && (ref.entry === 'finding' || ref.entry === 'group_member') && Boolean(ref.finding_id);
  const statusText = state === 'loading' ? `Loading ${title.toLowerCase()}` : `${title} ${state.replace('_', ' ')}`;

  const identity = (
    <dl className="ei-identity">
      {targetLabel ? <div><dt>{targetLabel === targetId ? 'Target ID' : 'Target'}</dt><dd className="mono">{targetLabel}</dd></div> : null}
      {checkLabel ? <div><dt>Check</dt><dd>{checkLabel}</dd></div> : null}
      {subject.title ? <div><dt>Finding</dt><dd>{subject.title}</dd></div> : null}
      {subject.lifecycle ? <div><dt>Lifecycle</dt><dd>{humanize(subject.lifecycle)}</dd></div> : null}
      {ref.entry === 'provider' && subject.provider ? <div><dt>Provider</dt><dd>{providerName(subject.provider)}</dd></div> : null}
      {ref.entry === 'audit' && subject.action ? <div><dt>Action</dt><dd className="mono">{subject.action}</dd></div> : null}
      {ref.entry === 'audit' && (subject.actor_user_id || subject.actor_role) ? <div><dt>Actor</dt><dd>{[subject.actor_user_id, subject.actor_role].filter(Boolean).join(' · ')}</dd></div> : null}
      {ref.entry === 'audit' && subject.resource_type ? <div><dt>Resource</dt><dd className="mono">{subject.resource_type}{subject.resource_id ? ` ${subject.resource_id}` : ''}</dd></div> : null}
      {ref.entry === 'audit' && subject.timestamp ? <div><dt>Recorded</dt><dd>{formatDate(subject.timestamp)}</dd></div> : null}
      {model?.primary?.observedAt ? <div><dt>Observed</dt><dd>{formatDate(model.primary.observedAt)}</dd></div> : null}
      <div><dt>Scope</dt><dd>External probes only</dd></div>
    </dl>
  );

  const actions: ReactNode[] = [];
  const hashParams = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
  const onSameTarget = window.location.hash.startsWith('#target-detail') && hashParams.get('id') === targetId;
  const onSameCheck = onSameTarget && Boolean(checkId) && hashParams.get('check') === checkId;
  if (targetId && ref.entry !== 'audit' && !(onSameTarget && (!checkId || ref.entry === 'provider' || onSameCheck))) {
    const checkParam = checkId ? `&tab=validate&check=${encodeURIComponent(checkId)}` : '';
    actions.push(
      <AnchorButton key="target" size="sm" variant="secondary" href={`#target-detail?id=${encodeURIComponent(targetId)}${checkParam}`}>
        {checkId ? 'Open this check on the target' : 'Open target'}
      </AnchorButton>,
    );
  }
  if ((ref.entry === 'finding' || ref.entry === 'group_member') && ref.finding_id) {
    actions.push(
      <AnchorButton key="finding" size="sm" variant="ghost" href={`#finding-detail?id=${encodeURIComponent(ref.finding_id)}`}>Open full finding</AnchorButton>,
    );
  }
  if (canRetest) {
    actions.push(
      <AnchorButton key="retest" size="sm" variant="ghost" href={`#finding-detail?id=${encodeURIComponent(ref.finding_id!)}&retest=review`}>Review retest</AnchorButton>,
    );
  }
  if (ref.entry === 'artifact' && ref.evidence_id) {
    actions.push(
      <AnchorButton key="artifact" size="sm" variant="ghost" href={`#evidence-detail?id=${encodeURIComponent(ref.evidence_id)}`}>Open artifact record</AnchorButton>,
    );
  }

  return (
    <InspectorPanel
      open
      title={title}
      accessibleTitle={title}
      eyebrow="Evidence inspector"
      status={statusText}
      busy={state === 'loading'}
      onClose={close}
      restoreFocus={restoreFocus}
      focusToken={refKey}
      meta={(
        <>
          {position ? (
            <nav className="ei-sequence" aria-label={`Step through ${position.noun}`}>
              <Button
                size="sm"
                variant="secondary"
                disabled={!position.previous}
                aria-label={position.previous ? `Previous: ${position.previous.label}` : 'No previous record'}
                onClick={() => position.previous && replaceEvidenceInspector(position.previous.ref)}
              >
                <ChevronLeft size={16} aria-hidden="true" />Previous
              </Button>
              <span className="ei-sequence-label">
                <span className="tabular-nums">{position.index + 1} of {position.total}</span>
                <span className="ei-sequence-current mono">{position.current.label}</span>
              </span>
              <Button
                size="sm"
                variant="secondary"
                disabled={!position.next}
                aria-label={position.next ? `Next: ${position.next.label}` : 'No next record'}
                onClick={() => position.next && replaceEvidenceInspector(position.next.ref)}
              >
                Next<ChevronRight size={16} aria-hidden="true" />
              </Button>
            </nav>
          ) : null}
          {identity}
        </>
      )}
      footer={actions.length ? <div className="ei-actions">{actions}</div> : undefined}
    >
      {state === 'loading' ? (
        <div className="ei-loading" aria-hidden="true">
          <div className="skeleton skeleton-row" />
          <div className="skeleton skeleton-row" />
          <div className="skeleton skeleton-row" />
        </div>
      ) : null}

      {state === 'auth' ? (
        <div className="ei-state" data-state="auth" role="note"><Lock size={18} aria-hidden="true" /><div><strong>Sign in again</strong><p>Your session ended. Sign in to load this evidence.</p></div></div>
      ) : null}

      <StateNotice state={state} permission={load.key === loadKey ? load.permission : ''} entry={ref.entry} onRetry={() => setReload((value) => value + 1)} />

      {load.key === loadKey && load.fallback && model && state !== 'no_refs' ? (
        <p className="ei-partial" role="note">
          Partial view from the exact {ref.entry === 'provider' ? 'target record' : ref.entry === 'check_result' ? 'execution record' : 'record'}.
          The evidence summary service did not answer, so request and response details are shown as not recorded here.
          <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}><RefreshCw size={14} aria-hidden="true" />Retry</Button>
        </p>
      ) : null}

      {model && state !== 'denied' && state !== 'not_found' ? (
        <>
          <section className="ei-answer" aria-label="What happened">
            {outcomeLabel ? (
              <p className="ei-outcome">
                <Badge tone={ref.entry === 'provider' ? providerTone(outcome) : outcomeTone(outcome)}>{outcomeLabel}</Badge>
                {ref.entry === 'provider' && ref.family ? <span className="ei-outcome-scope">{FAMILY_LABEL[ref.family]} only. Other layers are reported separately.</span> : null}
              </p>
            ) : (
              <p className="ei-outcome"><NotRecorded>Outcome not recorded</NotRecorded></p>
            )}
            {answer?.explanation ? <p className="ei-explanation">{answer.explanation}</p> : null}
            {(ref.entry === 'finding' || ref.entry === 'group_member') && outcomeTone(outcome) === 'success' && ['open', 'remediation_pending'].includes((subject.lifecycle ?? '').toLowerCase()) ? (
              <p className="ei-disagree" role="note">
                This finding is still open, but its original recorded outcome reads as passing. The records disagree; review the evidence before deciding. No later result was substituted.
              </p>
            ) : null}
            {model.limitations.length ? (
              <ul className="ei-limitations">
                {model.limitations.map((code) => <li key={code}>{limitationLabel(code)}</li>)}
              </ul>
            ) : null}
          </section>

          {!(load.key === loadKey && load.fallback) && ref.entry !== 'provider' && ref.entry !== 'artifact' && ref.entry !== 'report' && ref.entry !== 'audit' ? (
            <section className="ei-compare" aria-label="Expected versus observed">
              <div><span className="ei-label">Expected</span><strong>{answer?.expected ? humanize(answer.expected) : <NotRecorded />}</strong></div>
              <div><span className="ei-label">Observed</span><strong>{answer?.observed ? humanize(answer.observed) : <NotRecorded />}</strong></div>
            </section>
          ) : null}

          {!(load.key === loadKey && load.fallback) && (ref.entry === 'check_result' || ref.entry === 'finding' || ref.entry === 'group_member') ? (
            <section className="ei-exchange" aria-label="Request and response summary">
              <div>
                <h3>Request</h3>
                <SummaryFields fields={model.request.fields} empty="Request summary not recorded for this result" />
              </div>
              <div>
                <h3>Response</h3>
                <SummaryFields fields={model.response.fields} empty="Response summary not recorded for this result" />
              </div>
            </section>
          ) : null}

          {ref.entry === 'provider' ? (
            <section className="ei-evaluation" aria-label="How this was identified">
              <h3>How this was identified</h3>
              {model.proof && Object.values(model.proof).some((values) => values.length) ? (
                <dl className="ei-kv">
                  {model.proof.methods.length ? <div><dt>Methods</dt><dd>{model.proof.methods.join(', ')}</dd></div> : null}
                  {model.proof.matched_signals.length ? <div><dt>Matched signals</dt><dd className="mono">{model.proof.matched_signals.join(', ')}</dd></div> : null}
                  {model.proof.cnames.length ? <div><dt>CNAME chain</dt><dd className="mono">{model.proof.cnames.join(' > ')}</dd></div> : null}
                  {model.proof.addresses.length ? <div><dt>Address attribution</dt><dd className="mono">{model.proof.addresses.join(', ')}</dd></div> : null}
                  {model.proof.fingerprints.length ? <div><dt>Response fingerprints</dt><dd className="mono">{model.proof.fingerprints.join(', ')}</dd></div> : null}
                </dl>
              ) : <NotRecorded>No family-specific signal recorded for this layer</NotRecorded>}
              <dl className="ei-kv ei-kv-inline">
                <div><dt>Recorded confidence</dt><dd>{model.provider.confidence === null ? <NotRecorded /> : `${Math.round(model.provider.confidence <= 1 ? model.provider.confidence * 100 : model.provider.confidence)}%`}</dd></div>
                <div><dt>Signal conflict</dt><dd>{model.provider.conflict ? 'Signals conflict' : <NotRecorded>None recorded</NotRecorded>}</dd></div>
                <div><dt>Corpus</dt><dd className="mono">{model.provider.corpus || <NotRecorded />}</dd></div>
              </dl>
            </section>
          ) : null}

          {model.evaluation.fields.length ? (
            <section className="ei-evaluation" aria-label={ref.entry === 'provider' ? 'Recorded fields' : 'Evaluation'}>
              <h3>{ref.entry === 'provider' ? 'Recorded fields' : 'Evaluation'}</h3>
              <SummaryFields
                fields={model.evaluation.fields.map((field) => (field.key === 'provider' ? { ...field, value: providerName(field.value) } : field))}
                empty="Evaluation reasons not recorded"
              />
            </section>
          ) : null}

          <section className="ei-provenance" aria-label="Provenance">
            {model.primary ? (
              <ObservationBlock
                title={ref.entry === 'finding' || ref.entry === 'group_member' ? 'Original evidence' : 'Recorded observation'}
                note={ref.entry === 'finding' || ref.entry === 'group_member' ? 'The observation that opened this finding.' : 'The exact record this result came from.'}
                observation={model.primary}
                missingIds={model.missingEvidenceIds}
              />
            ) : model.originating && (model.originating.testRunId || model.originating.verdictId) ? (
              <ObservationBlock
                title="Original evidence"
                note="The record that opened this finding. It cites no evidence reference, so no artifact is shown."
                observation={model.originating}
              />
            ) : state !== 'no_refs' && ref.entry !== 'audit' ? <NotRecorded>No originating observation recorded</NotRecorded> : null}
            {model.later ? (
              <ObservationBlock
                title="Later result, same target and check"
                note="Shown separately. It does not replace the original evidence or close this finding."
                observation={model.later}
              />
            ) : null}
            {model.alternatives.length ? (
              <details className="ei-alternatives">
                <summary>{model.alternatives.length} related record{model.alternatives.length === 1 ? '' : 's'}</summary>
                {model.alternatives.map((alt, index) => (
                  <ObservationBlock key={`${alt.testRunId}-${index}`} title="Related record" note={humanize(alt.relationship)} observation={alt} />
                ))}
              </details>
            ) : null}
          </section>

          <details className="ei-technical">
            <summary>Technical record</summary>
            <dl className="ei-kv">
              {Object.entries(subject).map(([key, value]) => (
                <div key={key}><dt>{humanize(key)}</dt><dd className="mono">{value}</dd></div>
              ))}
              <div><dt>Entry</dt><dd className="mono">{ref.entry}</dd></div>
            </dl>
          </details>
        </>
      ) : null}
    </InspectorPanel>
  );
}
