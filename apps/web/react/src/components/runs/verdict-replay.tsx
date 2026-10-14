import { useEffect, useId, useRef, useState } from 'react';
import { BadgeCheck, History, Info, ShieldQuestion } from 'lucide-react';
import { requestJson } from '../../lib/api';
import type { PortalConfig, Session } from '../../lib/types';
import { verdictTone } from '../../lib/status-tone';
import { verdictReplayErrorMessage, verdictReplayModel, type VerdictReplayModel } from '../../lib/verdict-replay.mjs';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import './verdict-replay.css';

type ReplayState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ready'; model: VerdictReplayModel }
  | { status: 'error'; message: string };

function Versions({ value }: { value: string }) {
  if (!value) return <>not recorded</>;
  return <>{value.split(' · ').map((part, index) => <span key={part}>{index ? ' and ' : ''}<span className="mono vr-version">{part}</span></span>)}</>;
}

function Outcome({ model }: { model: VerdictReplayModel }) {
  if (model.state === 'no_evidence') {
    return <p className="vr-line">No stored probe evidence for this run, so it cannot be re-checked. Re-run the check to record new evidence.</p>;
  }
  if (model.state === 'no_stored') {
    return (
      <p className="vr-line">
        No verdict was stored for this run. Current rules would give <Badge tone={verdictTone(model.nowVerdict)}>{model.nowLabel || 'No result'}</Badge>
      </p>
    );
  }
  if (model.state === 'changed') {
    return (
      <>
        <p className="vr-line vr-headline">
          <strong>Would now be</strong> <Badge tone={verdictTone(model.nowVerdict)}>{model.nowLabel || 'No result'}</Badge>
          <span className="vr-was">stored as <Badge tone="muted">{model.storedLabel}</Badge></span>
        </p>
        <p className="vr-copy">The stored verdict is not changed. Re-run the check to record a verdict under the current rules.</p>
      </>
    );
  }
  return (
    <p className="vr-line vr-headline">
      <Badge tone="muted">Unchanged</Badge>
      <span>Current rules give the same result: <Badge tone={verdictTone(model.storedVerdict)}>{model.storedLabel}</Badge></span>
    </p>
  );
}

/** On-demand re-check of a stored verdict against current rules; fetches only when asked and never writes. */
export function VerdictReplay({ config, session, runId }: { config: PortalConfig; session: Session; runId: string }) {
  const [state, setState] = useState<ReplayState>({ status: 'idle' });
  const helpId = useId();
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    setState({ status: 'idle' });
    return () => { active.current = false; };
  }, [runId]);

  async function recheck() {
    setState({ status: 'loading' });
    try {
      const payload = await requestJson(config, session, `/v1/test-runs/${encodeURIComponent(runId)}/verdict-replay`);
      if (!active.current) return;
      const model = verdictReplayModel(payload);
      setState(model ? { status: 'ready', model } : { status: 'error', message: verdictReplayErrorMessage(null) });
    } catch (error) {
      if (active.current) setState({ status: 'error', message: verdictReplayErrorMessage(error) });
    }
  }

  if (!runId) return null;
  const done = state.status === 'ready' || state.status === 'error';
  return (
    <section className="vr" aria-label="Re-check this verdict">
      <div className="vr-head">
        <Button size="sm" variant={done ? 'ghost' : 'secondary'} loading={state.status === 'loading'} loadingText="Re-checking…" aria-describedby={helpId} onClick={() => void recheck()}>
          <History size={14} aria-hidden="true" />{done ? 'Re-check again' : 'Re-check this verdict with current rules'}
        </Button>
        <p className="vr-help" id={helpId}>Replays this run's stored evidence through today's grading rules and your current control declarations. Sends no traffic and changes nothing.</p>
      </div>
      <div className="vr-result" role="status" aria-live="polite" aria-atomic="true">
        {state.status === 'ready' ? (
          <>
            <Outcome model={state.model} />
            {state.model.explanation && state.model.state !== 'no_evidence' ? <p className="vr-copy">{state.model.explanation}</p> : null}
            {state.model.regrade && state.model.state !== 'no_evidence' ? (
              <p className="vr-regrade" data-regraded={state.model.regrade.regraded ? 'true' : 'false'}>
                {state.model.regrade.regraded ? <BadgeCheck size={15} aria-hidden="true" /> : <Info size={15} aria-hidden="true" />}
                <span><b>{state.model.regrade.label}.</b> {state.model.regrade.note}</span>
              </p>
            ) : null}
            {state.model.versionGap ? (
              <p className="vr-note">
                <ShieldQuestion size={15} aria-hidden="true" />
                <span>
                  <b>{state.model.versionGap.label}.</b>{' '}
                  {state.model.storedVersions ? <>Stored under <Versions value={state.model.storedVersions} />; current rules are <Versions value={state.model.currentVersions} />. </> : null}
                  Until it is re-run, this result earns no readiness credit.
                </span>
              </p>
            ) : null}
            {state.model.declarationsApplied ? <p className="vr-meta">Used this target's current control declarations.</p> : null}
          </>
        ) : state.status === 'error' ? <p className="vr-copy">{state.message}</p> : null}
      </div>
    </section>
  );
}
