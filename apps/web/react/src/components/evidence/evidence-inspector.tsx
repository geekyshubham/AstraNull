import { checkPresentation } from '../../lib/check-presentation.mjs';
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Check, ChevronLeft, ChevronRight, Circle, CircleAlert, CircleDashed, Lock, RefreshCw, SearchX, ShieldCheck, TriangleAlert, X } from 'lucide-react';
import { requestJson } from '../../lib/api';
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
  inspectorWorkspaceKey,
  limitationLabel,
  normalizeEvidenceContext,
  openEvidenceInspector,
  ORIGINATING_RUN_ARTIFACT,
  parseInspectorRef,
  relationshipLabel,
  replaceEvidenceInspector,
  type EvidenceContextModel,
  type EvidenceInspectorRef,
  type InspectorObservation,
  type InspectorState,
} from '../../lib/evidence-inspector.mjs';
import { canAccessRoute } from '../../lib/route-access';
import { canStartRun } from '../../lib/run-permissions.mjs';
import type { DataItem, PortalConfig, PortalData, Session } from '../../lib/types';
import { formatTimestamp } from '../../lib/utils';
import { plainCheckName, plainVerdictLabel } from '../../lib/plain-language.mjs';
import { providerName } from '../../lib/domain-checks.mjs';
import { exposedVerdictLabel } from '../../lib/probe-evidence.mjs';
import { Badge } from '../ui/badge';
import { AnchorButton, Button } from '../ui/button';
import { InspectorPanel } from '../ui/inspector-panel';
import { AskAiButton } from '../assistant/ask-ai-button';
import { sequencePosition, useInspectorSequence } from './inspector-sequence';
import { ExecutionInspector } from './execution-inspector';
import { NotTestedNote } from '../runs/not-tested-note';
import { requiredInputMissing } from '../../lib/missing-input.mjs';
import { evidenceStory, proofRows } from '../../lib/evidence-story.mjs';
import { useInspectorScopeKey } from './use-inspector';
import './evidence-inspector.css';

type Tone = 'success' | 'warn' | 'danger' | 'info' | 'muted' | 'default';

const ENTRY_TITLE: Record<EvidenceInspectorRef['entry'], string> = {
  finding: 'Finding evidence',
  group_member: 'Affected target evidence',
  check_result: 'Check result',
  validation_scan: 'Validation scan',
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
  requests_sent: 'Recorded logical operations',
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
  if (status === 'verified' && integrity.verifiedAt) return `Verified ${formatTimestamp(integrity.verifiedAt)}${integrity.method ? ` (${integrity.method})` : ''}`;
  if (status === 'verified') return 'Reported verified, but no verification time is recorded. Treat as not verified.';
  if (status === 'failed' || status === 'verification_failed') return `Verification failed${integrity.verifiedAt ? ` ${formatTimestamp(integrity.verifiedAt)}` : ''}.`;
  if (status === 'partial') return 'Some referenced records are verified and some are not; see each record.';
  if (status === 'recorded_digest') return 'Digest recorded. Not independently verified.';
  return 'No integrity record for these references.';
}

function ObservationBlock({ title, note, observation, missingIds = [], onViewArtifact }: {
  title: string;
  note: string;
  observation: InspectorObservation;
  missingIds?: string[];
  onViewArtifact?: (evidenceId: string, testRunId: string) => void;
}) {
  const integrity = observation.integrity;
  return (
    <section className="ei-observation" aria-label={title}>
      <header>
        <strong>{title}</strong>
        <span className="ei-note">{note}</span>
      </header>
      <dl className="ei-kv">
        <div><dt>Observed</dt><dd>{observation.observedAt ? formatTimestamp(observation.observedAt) : <NotRecorded />}</dd></div>
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
                    {onViewArtifact ? (
                      <Button size="sm" variant="ghost" aria-label={`View artifact ${id}`} onClick={() => onViewArtifact(id, observation.testRunId)}>View</Button>
                    ) : null}
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

function StateNotice({ state, permission, onRetry, entry, runArtifacts = 0 }: { state: InspectorState; permission: string; onRetry: () => void; entry: string; runArtifacts?: number }) {
  if (state === 'pending') {
    return (
      <div className="ei-state" data-state="pending" role="note">
        <CircleDashed size={18} aria-hidden="true" />
        <div>
          <strong>Collecting — verdict not yet correlated</strong>
          <p>Probe responses below are observations, not a verdict. Evidence is attached when the verdict is published.</p>
        </div>
      </div>
    );
  }
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
        : (entry === 'finding' || entry === 'group_member') && runArtifacts > 0
          ? { title: 'Supporting evidence not cited by this finding', body: `This finding cites no evidence reference. ${runArtifacts === 1 ? '1 artifact was recorded for its originating run and is' : `${runArtifacts} artifacts were recorded for its originating run and are`} listed below.` }
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
  return checkPresentation(checkId).name;
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
  const scopeKey = useInspectorScopeKey(config, session);
  const refKey = inspectorRefKey(ref);
  const workspaceKey = inspectorLoadKey(scopeKey, inspectorWorkspaceKey(ref));
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
    setLoad((previous) => previous.key === loadKey && previous.model ? previous : { key: loadKey, model: null, state: 'loading', permission: '', fallback: false });
    const current = () => generation.current.isCurrent(token);
    if (ref.entry === 'validation_scan') {
      // The existing exact assessment reader supplies its own passive state and child workspace.
      setLoad({ key: loadKey, model: null, state: 'ready', permission: '', fallback: false });
      return () => controller.abort();
    }

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
          const classifiedState = classified.state;
          setLoad((previous) => ({ key: loadKey, model: classifiedState === 'unavailable' && previous.key === loadKey ? previous.model : null, state: classifiedState, permission: classified.permission, fallback: false }));
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

  const findingIdForArtifacts = ref?.finding_id ?? '';
  const viewRunArtifact = useCallback((evidenceId: string, testRunId: string) => {
    openEvidenceInspector({
      entry: 'artifact',
      evidence_id: evidenceId,
      ...(testRunId ? { test_run_id: testRunId } : {}),
      ...(findingIdForArtifacts ? { finding_id: findingIdForArtifacts } : {}),
    });
  }, [findingIdForArtifacts]);

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

  const refreshExecutionEvidence = useCallback((state?: 'denied' | 'auth' | 'not_found') => {
    if (state) {
      generation.current.cancel();
      setLoad({ key: loadKey, model: null, state, permission: '', fallback: false });
    } else setReload((value) => value + 1);
  }, [loadKey]);

  if (!ref || !view) return null;

  const { model, state, targetId, checkId, targetLabel, checkLabel, subject } = view;
  const position = sequencePosition(sequence, ref);
  const title = ref.entry === 'provider'
    ? `${ENTRY_TITLE.provider}: ${FAMILY_LABEL[ref.family ?? ''] ?? 'Provider'}`
    : ENTRY_TITLE[ref.entry];
  const answer = model?.answer ?? null;
  const outcome = answer?.outcome ?? '';
  const notTested = ref.entry === 'provider' || !answer ? null : requiredInputMissing({ explanation_reason: answer.reason, required_input: answer.requiredInput, explanation: answer.explanation });
  const outcomeLabel = notTested ? notTested.label : outcome
    ? ref.entry === 'provider' ? humanize(outcome) : exposedVerdictLabel(checkId, outcome) || plainVerdictLabel(outcome) || humanize(outcome)
    : '';
  const canRetest = canStartRun(session.role) && (ref.entry === 'finding' || ref.entry === 'group_member') && Boolean(ref.finding_id);
  const statusText = state === 'loading' ? `Loading ${title.toLowerCase()}` : `${title} ${state.replace('_', ' ')}`;

  const check = checkId ? data.checks.find((item) => str(item, ['check_id', 'id']) === checkId) ?? null : null;
  const probeProfile = check?.probe_profile && typeof check.probe_profile === 'object' && !Array.isArray(check.probe_profile) ? check.probe_profile as DataItem : null;
  const isFallback = load.key === loadKey && load.fallback;
  const storyEntry = ref.entry === 'finding' || ref.entry === 'group_member' || ref.entry === 'check_result';
  const story = storyEntry && model && answer
    ? evidenceStory({
      checkId,
      vectorFamily: str(check, ['vector_family']),
      outcome,
      notTested: Boolean(notTested),
      observationOnly: check?.observation_only === true || probeProfile?.observation_only === true,
      remediation: str(check, ['remediation_template']) || subject.remediation_template || '',
      explanation: answer.explanation,
    })
    : null;
  const observedLabel = answer?.observed ? exposedVerdictLabel(checkId, answer.observed) || plainVerdictLabel(answer.observed) || humanize(answer.observed) : '';
  const proof = story && model ? proofRows({
    tone: story.tone,
    observed: observedLabel,
    expected: answer?.expected ? humanize(answer.expected) : '',
    request: isFallback ? [] : model.request.fields,
    response: isFallback ? [] : model.response.fields,
    proof: model.proof,
  }) : [];
  const VerdictIcon = story?.tone === 'gap' ? TriangleAlert : story?.tone === 'pass' ? ShieldCheck : story?.tone === 'review' ? CircleAlert : CircleDashed;
  const subtitle = [targetLabel, checkLabel].filter(Boolean).join(' · ');

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
      {ref.entry === 'audit' && subject.timestamp ? <div><dt>Recorded</dt><dd>{formatTimestamp(subject.timestamp)}</dd></div> : null}
      {model?.primary?.observedAt ? <div><dt>Observed</dt><dd>{formatTimestamp(model.primary.observedAt)}</dd></div> : null}
      {ref.test_run_id ? <div><dt>Exact run</dt><dd className="mono">{ref.test_run_id}</dd></div> : null}
      {ref.scan_id ? <div><dt>Scan</dt><dd className="mono">{ref.scan_id}</dd></div> : null}
      <div><dt>Scope</dt><dd>External probes only</dd></div>
    </dl>
  );

  const actions: ReactNode[] = [];
  const hashParams = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
  if (canRetest) {
    actions.push(
      <AnchorButton key="retest" size="sm" variant="default" href={`#finding-detail?id=${encodeURIComponent(ref.finding_id!)}&retest=review`}>Re-test</AnchorButton>,
    );
  }
  if ((ref.entry === 'finding' || ref.entry === 'group_member') && ref.finding_id) {
    actions.push(
      <AnchorButton key="finding" size="sm" variant="secondary" href={`#finding-detail?id=${encodeURIComponent(ref.finding_id)}`}>Open finding</AnchorButton>,
      <AskAiButton
        key="ask-ai"
        config={config}
        session={session}
        variant="ghost"
        context={{ finding_id: ref.finding_id, ...(targetId ? { target_id: targetId } : {}), label: subject.title || targetLabel || 'This finding' }}
      />,
    );
  }
  const onSameTarget = window.location.hash.startsWith('#target-detail') && hashParams.get('id') === targetId;
  const onSameCheck = onSameTarget && Boolean(checkId) && hashParams.get('check') === checkId;
  if (targetId && ref.entry !== 'audit' && !(onSameTarget && (!checkId || ref.entry === 'provider' || onSameCheck))) {
    const checkParam = checkId ? `&tab=validate&check=${encodeURIComponent(checkId)}` : '';
    actions.push(
      <AnchorButton key="target" size="sm" variant={actions.length ? 'ghost' : 'secondary'} href={`#target-detail?id=${encodeURIComponent(targetId)}${checkParam}`}>
        {checkId ? 'Open target check' : 'Open target'}
      </AnchorButton>,
    );
  }
  const onSameRun = window.location.hash.startsWith('#run-detail') && hashParams.get('id') === ref.test_run_id;
  if (ref.test_run_id && !onSameRun) {
    actions.push(
      <AnchorButton key="run" size="sm" variant="ghost" href={`#run-detail?id=${encodeURIComponent(ref.test_run_id)}`}>Open run</AnchorButton>,
    );
  }
  if (ref.entry === 'artifact' && ref.evidence_id) {
    actions.push(
      <AnchorButton key="artifact" size="sm" variant="ghost" href={`#evidence-detail?id=${encodeURIComponent(ref.evidence_id)}`}>Open artifact record</AnchorButton>,
    );
  }

  const outcomeBadge = outcomeLabel ? (
    <Badge tone={notTested ? 'muted' : ref.entry === 'provider' ? providerTone(outcome) : outcomeTone(outcome)}>{outcomeLabel}</Badge>
  ) : null;
  const disagree = (ref.entry === 'finding' || ref.entry === 'group_member') && outcomeTone(outcome) === 'success' && ['open', 'remediation_pending'].includes((subject.lifecycle ?? '').toLowerCase());

  return (
    <InspectorPanel
      open
      title={title}
      accessibleTitle={title}
      status={statusText}
      busy={state === 'loading'}
      onClose={close}
      restoreFocus={restoreFocus}
      focusToken={workspaceKey}
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
          {subtitle || ref.test_run_id ? (
            <p className="ei-subtitle">
              {subtitle}
              {ref.test_run_id ? <>{subtitle ? ' · ' : ''}Run <span className="mono">{ref.test_run_id}</span></> : null}
            </p>
          ) : null}
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

      <StateNotice state={notTested && state === 'no_refs' ? 'ready' : state} permission={load.key === loadKey ? load.permission : ''} entry={ref.entry} runArtifacts={model?.runArtifacts ?? 0} onRetry={() => setReload((value) => value + 1)} />

      {(ref.entry === 'check_result' || ref.entry === 'validation_scan') && !['denied', 'auth', 'not_found', 'unbound', 'expired'].includes(state) ? (
        <ExecutionInspector key={workspaceKey} config={config} session={session} reference={ref} checks={data.checks} onEvidenceUpdate={refreshExecutionEvidence} />
      ) : null}

      {model && state !== 'denied' && state !== 'not_found' ? (
        <>
          {story ? (
            <section className="ei-verdict" data-tone={story.tone} aria-label="Conclusion">
              <span className="ei-verdict-icon" aria-hidden="true"><VerdictIcon size={18} /></span>
              <div className="ei-verdict-copy">
                <span className="ei-kicker">{story.kicker}</span>
                <h3 className="ei-headline">{story.headline}</h3>
                <span className="ei-verdict-meta">
                  {outcomeBadge}
                  {model.primary?.observedAt ? <span>Observed {formatTimestamp(model.primary.observedAt)}</span> : null}
                </span>
              </div>
            </section>
          ) : (
            <section className="ei-answer" aria-label="What happened">
              {outcomeBadge ? (
                <p className="ei-outcome">
                  {outcomeBadge}
                  {ref.entry === 'provider' && ref.family ? <span className="ei-outcome-scope">{FAMILY_LABEL[ref.family]} only. Other layers are reported separately.</span> : null}
                </p>
              ) : (
                <p className="ei-outcome"><NotRecorded>{state === 'pending' ? 'Verdict pending' : 'Outcome not recorded'}</NotRecorded></p>
              )}
              {!notTested && answer?.explanation ? <p className="ei-explanation">{answer.explanation}</p> : null}
            </section>
          )}

          {notTested ? <NotTestedNote info={notTested} targetId={targetId} showLabel={false} /> : null}

          {disagree ? (
            <p className="ei-disagree" role="note">
              This finding is still open, but its original recorded outcome reads as passing. The records disagree; review the evidence before deciding. No later result was substituted.
            </p>
          ) : null}

          {story && proof.length ? (
            <section className="ei-story" aria-labelledby="ei-saw-title">
              <h3 className="ei-story-title" id="ei-saw-title">What we saw</h3>
              {story.tested ? <p className="ei-story-note">{story.tested}</p> : null}
              <ul className="ei-proof">
                {proof.map((row) => (
                  <li key={row.key} data-tone={row.tone}>
                    <span className="ei-proof-icon" aria-hidden="true">
                      {row.tone === 'fail' ? <X size={16} /> : row.tone === 'pass' ? <Check size={16} /> : <Circle size={14} />}
                    </span>
                    <span className="ei-proof-copy">
                      <strong>{row.title}</strong>
                      {row.detail ? <span className="mono">{row.detail}</span> : null}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {story?.why ? (
            <section className="ei-story" aria-labelledby="ei-why-title">
              <h3 className="ei-story-title" id="ei-why-title">Why it matters</h3>
              <p className="ei-story-body">{story.why}</p>
            </section>
          ) : null}

          {story?.fix.length ? (
            <section className="ei-story" aria-labelledby="ei-fix-title">
              <h3 className="ei-story-title" id="ei-fix-title">How to fix</h3>
              <ol className="ei-fix">
                {story.fix.map((step) => <li key={step}>{step}</li>)}
              </ol>
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

          <details className="ei-technical" open={(!model.primary && model.runArtifacts > 0) || undefined}>
            <summary>{storyEntry ? 'Technical details · Original evidence, run and records' : 'Technical details · Recorded observation and records'}</summary>
            <div className="ei-technical-body">
              {identity}

              {isFallback && state !== 'no_refs' && state !== 'pending' ? (
                <p className="ei-partial" role="note">
                  Partial view from the exact {ref.entry === 'provider' ? 'target record' : ref.entry === 'check_result' ? 'execution record' : 'record'}.
                  The evidence summary service did not answer, so request and response details are shown as not recorded here.
                  <Button size="sm" variant="ghost" onClick={() => setReload((value) => value + 1)}><RefreshCw size={14} aria-hidden="true" />Retry</Button>
                </p>
              ) : null}

              {story && answer?.explanation ? <p className="ei-explanation">{answer.explanation}</p> : null}

              {model.limitations.length ? (
                <ul className="ei-limitations">
                  {model.limitations.map((code) => <li key={code}>{limitationLabel(code)}</li>)}
                </ul>
              ) : null}

              {!isFallback && ref.entry !== 'provider' && ref.entry !== 'artifact' && ref.entry !== 'report' && ref.entry !== 'audit' ? (
                <section className="ei-compare" aria-label="Expected versus observed">
                  <div><span className="ei-label">Expected</span><strong>{answer?.expected ? humanize(answer.expected) : <NotRecorded />}</strong></div>
                  <div><span className="ei-label">Observed</span><strong>{answer?.observed ? humanize(answer.observed) : <NotRecorded />}</strong></div>
                </section>
              ) : null}

              {!isFallback && storyEntry ? (
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
                    title={ref.entry === 'finding' || ref.entry === 'group_member' ? 'Opening observation' : 'Recorded observation'}
                    note={ref.entry === 'finding' || ref.entry === 'group_member' ? 'The observation that opened this finding.' : 'The exact record this result came from.'}
                    observation={model.primary}
                    missingIds={model.missingEvidenceIds}
                  />
                ) : model.originating && (model.originating.testRunId || model.originating.verdictId) ? (
                  <ObservationBlock
                    title="Opening observation"
                    note={model.runArtifacts > 0
                      ? 'The record that opened this finding. It cites no evidence reference; artifacts recorded for its run are listed under related records.'
                      : 'The record that opened this finding. It cites no evidence reference.'}
                    observation={model.originating}
                  />
                ) : state !== 'no_refs' && state !== 'pending' && ref.entry !== 'audit' ? <NotRecorded>No originating observation recorded</NotRecorded> : null}
                {model.later ? (
                  <ObservationBlock
                    title="Later result, same target and check"
                    note="Shown separately. It does not replace the original evidence or close this finding."
                    observation={model.later}
                  />
                ) : null}
                {model.alternatives.length ? (
                  <details className="ei-alternatives" open={model.runArtifacts > 0 || undefined}>
                    <summary>{model.alternatives.length} related record{model.alternatives.length === 1 ? '' : 's'}</summary>
                    {model.alternatives.map((alt, index) => (
                      <ObservationBlock
                        key={`${alt.testRunId}-${index}`}
                        title={alt.relationship === ORIGINATING_RUN_ARTIFACT ? 'Run artifact' : 'Related record'}
                        note={relationshipLabel(alt.relationship)}
                        observation={alt}
                        onViewArtifact={alt.relationship === ORIGINATING_RUN_ARTIFACT ? viewRunArtifact : undefined}
                      />
                    ))}
                  </details>
                ) : null}
              </section>

              <dl className="ei-kv">
                {Object.entries(subject).map(([key, value]) => (
                  <div key={key}><dt>{humanize(key)}</dt><dd className="mono">{value}</dd></div>
                ))}
                <div><dt>Entry</dt><dd className="mono">{ref.entry}</dd></div>
              </dl>
            </div>
          </details>
        </>
      ) : null}
    </InspectorPanel>
  );
}
