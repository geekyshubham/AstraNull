import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { AlertOctagon, AlertTriangle, ArrowUpRight, CheckCircle2, Info, MessageSquareText, RefreshCw, Sparkles, X } from 'lucide-react';
import { openAssistant } from '../../lib/assistant-bus';
import { useInsights } from '../../lib/assistant-insights-api';
import {
  formatKpi,
  kpiUnitSuffix,
  narrativeUnavailableMessage,
  type InsightAction,
  type InsightKpi,
  type InsightScope,
  type InsightTone,
} from '../../lib/assistant-insights.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { Button } from '../ui/button';
import { AssistantVisual } from './assistant-visual';
import './insights.css';

const TONE_LABEL: Record<InsightTone, string> = { critical: 'Needs attention', caution: 'Watch', positive: 'Healthy', neutral: 'Information' };

function ToneIcon({ tone, size = 18 }: { tone: InsightTone; size?: number }) {
  if (tone === 'critical') return <AlertOctagon size={size} aria-hidden="true" />;
  if (tone === 'caution') return <AlertTriangle size={size} aria-hidden="true" />;
  if (tone === 'positive') return <CheckCircle2 size={size} aria-hidden="true" />;
  return <Info size={size} aria-hidden="true" />;
}

function useElapsed(running: boolean) {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    if (!running) return undefined;
    setSeconds(0);
    const started = Date.now();
    const timer = window.setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [running]);
  return seconds;
}

function Kpi({ kpi }: { kpi: InsightKpi }) {
  return (
    <li className="ai-ins-kpi" data-tone={kpi.tone}>
      <span className="ai-ins-kpi-label">{kpi.label}</span>
      <span className="ai-ins-kpi-value tabular-nums">
        {formatKpi(kpi)}
        <span className="ai-ins-kpi-unit">{kpiUnitSuffix(kpi)}</span>
      </span>
      {kpi.detail ? <span className="ai-ins-kpi-detail">{kpi.detail}</span> : null}
      {kpi.tone !== 'neutral' ? (
        <span className="ai-ins-kpi-tone"><ToneIcon tone={kpi.tone} size={12} />{TONE_LABEL[kpi.tone]}</span>
      ) : null}
    </li>
  );
}

function ActionRow({ action, onOpen }: { action: InsightAction; onOpen: (route: string) => void }) {
  return (
    <li className="ai-ins-action" data-severity={action.severity}>
      <span className="ai-ins-sev">{action.severity === 'unknown' ? 'Note' : action.severity}</span>
      <span className="ai-ins-action-body">
        <strong>{action.title}</strong>
        {action.detail ? <span>{action.detail}</span> : null}
      </span>
      {action.route ? (
        <Button size="sm" variant="ghost" className="ai-ins-open" onClick={() => onOpen(action.route ?? '')} aria-label={`Open: ${action.title}`}>
          Open<ArrowUpRight size={14} aria-hidden="true" />
        </Button>
      ) : null}
    </li>
  );
}

function Skeleton({ seconds }: { seconds: number }) {
  return (
    <div className="ai-ins-skeleton" aria-hidden="true">
      <p className="ai-ins-progress"><span className="ai-ins-pulse" />Reading your workspace… {seconds}s</p>
      <div className="ai-ins-sk ai-ins-sk-hero" />
      <div className="ai-ins-sk-row">{['a', 'b', 'c', 'd'].map((key) => <div key={key} className="ai-ins-sk ai-ins-sk-kpi" />)}</div>
      <div className="ai-ins-sk-row">{['a', 'b'].map((key) => <div key={key} className="ai-ins-sk ai-ins-sk-chart" />)}</div>
    </div>
  );
}

function Section({ title, children, id }: { title: string; children: ReactNode; id: string }) {
  return (
    <section className="ai-ins-block" aria-labelledby={id}>
      <h3 id={id} className="ai-ins-block-title">{title}</h3>
      {children}
    </section>
  );
}

const ERROR_COPY: Record<string, string> = {
  forbidden: 'Your role cannot open insights for this page.',
  not_found: 'This record is no longer available, so there is nothing to analyse.',
  disabled: 'AI insights are turned off for this workspace.',
  failed: 'Insights could not be loaded. Try again in a moment.',
};

export function InsightsDialog({ config, session, scope, open, onClose }: {
  config: PortalConfig;
  session: Session;
  scope: InsightScope;
  open: boolean;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const ids = useId();
  const insights = useInsights(config, session, scope, open);
  const loadingSeconds = useElapsed(insights.phase === 'loading');
  const narrativeSeconds = useElapsed(insights.narrativePending);
  const board = insights.phase === 'ready' ? insights.board : null;
  const narrative = insights.narrative ?? board?.narrative ?? null;
  const unavailable = insights.narrativeFailed
    ? 'The AI summary did not finish, so the computed summary is shown.'
    : narrativeUnavailableMessage(insights.narrativeState);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  function goTo(route: string) {
    onClose();
    window.location.hash = `#${route}`;
  }

  function askInChat() {
    onClose();
    const subject = board?.subject ?? scope.subject;
    openAssistant({ prompt: `Explain the insights for ${subject ? `${scope.label.toLowerCase()} ${subject}` : `the ${scope.label} page`} and tell me what to fix first.`, send: true });
  }

  const subject = board?.subject ?? scope.subject;

  return (
    <dialog
      ref={ref}
      className="ai-ins"
      aria-labelledby={titleId}
      aria-busy={insights.phase === 'loading' || insights.refreshing || undefined}
      onClose={onClose}
      onCancel={(event) => { event.preventDefault(); onClose(); }}
      onClick={(event) => { if (event.target === ref.current) onClose(); }}
    >
      <div className="ai-ins-frame">
        <header className="ai-ins-head">
          <span className="ai-ins-mark" aria-hidden="true"><Sparkles size={16} /></span>
          <div className="ai-ins-titles">
            <p className="ai-ins-eyebrow">AI insights</p>
            <h2 id={titleId} className="ai-ins-title">
              {scope.label}{subject ? <span className="ai-ins-subject">{subject}</span> : null}
            </h2>
          </div>
          <Button size="icon" variant="ghost" className="ai-ins-close" onClick={onClose} aria-label="Close AI insights">
            <X size={18} aria-hidden="true" />
          </Button>
        </header>

        <div className="ai-ins-body">
          {insights.phase === 'loading' ? <Skeleton seconds={loadingSeconds} /> : null}
          {insights.phase === 'loading' ? <p className="sr-only" role="status">Loading insights</p> : null}

          {insights.phase === 'error' ? (
            <div className="ai-ins-error" role="alert">
              <AlertTriangle size={18} aria-hidden="true" />
              <p>{ERROR_COPY[insights.error ?? 'failed']}</p>
              {insights.error === 'failed' ? <Button size="sm" variant="secondary" onClick={insights.reload}>Try again</Button> : null}
            </div>
          ) : null}

          {board ? (
            <div className={insights.refreshing ? 'ai-ins-board is-refreshing' : 'ai-ins-board'}>
              <section className="ai-ins-verdict" data-tone={board.verdict.tone} aria-label="Verdict">
                <span className="ai-ins-verdict-icon"><ToneIcon tone={board.verdict.tone} size={22} /></span>
                <div className="ai-ins-verdict-text">
                  <span className="ai-ins-verdict-tone">{TONE_LABEL[board.verdict.tone]}</span>
                  <p className="ai-ins-headline">{board.verdict.headline}</p>
                </div>
                {board.verdict.score !== null ? (
                  <div className="ai-ins-score" style={{ ['--ai-ins-score' as string]: board.verdict.score }}>
                    <span className="ai-ins-score-value tabular-nums">{board.verdict.score}<small>/100</small></span>
                    <span className="ai-ins-score-track" role="meter" aria-label="Score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={board.verdict.score}><span /></span>
                  </div>
                ) : null}
              </section>

              {board.kpis.length ? <ul className="ai-ins-kpis" aria-label="Key numbers">{board.kpis.map((kpi) => <Kpi key={kpi.id} kpi={kpi} />)}</ul> : null}

              {!board.noAccess ? (
                <section className="ai-ins-summary" aria-labelledby={`${ids}-summary`} data-ai={narrative?.ai ? 'true' : 'false'}>
                  <header className="ai-ins-summary-head">
                    <h3 id={`${ids}-summary`} className="ai-ins-block-title">Summary</h3>
                    {insights.narrativePending ? (
                      <span className="ai-ins-badge is-pending"><span className="ai-ins-pulse" />Writing AI summary… {narrativeSeconds}s</span>
                    ) : narrative?.ai ? (
                      <span className="ai-ins-badge is-ai"><Sparkles size={12} aria-hidden="true" />AI-written</span>
                    ) : (
                      <span className="ai-ins-badge">Computed</span>
                    )}
                  </header>
                  {narrative ? <p className="ai-ins-summary-text">{narrative.summary}</p> : null}
                  {narrative?.ai && narrative.takeaways.length ? (
                    <ol className="ai-ins-takeaways">{narrative.takeaways.map((item) => <li key={item}>{item}</li>)}</ol>
                  ) : null}
                  {insights.narrativePending ? (
                    <div className="ai-ins-sk-lines" aria-hidden="true"><span /><span /><span /></div>
                  ) : null}
                  {!insights.narrativePending && !narrative?.ai && unavailable ? <p className="ai-ins-note">{unavailable}</p> : null}
                  <p className="sr-only" role="status">{insights.narrativePending ? '' : narrative?.ai ? 'AI summary ready' : ''}</p>
                </section>
              ) : null}

              {board.actions.length ? (
                <Section id={`${ids}-actions`} title="What to do first">
                  <ol className="ai-ins-actions">{board.actions.map((action) => <ActionRow key={`${action.title}-${action.route ?? ''}`} action={action} onOpen={goTo} />)}</ol>
                </Section>
              ) : null}

              {board.sections.length ? (
                <Section id={`${ids}-charts`} title="Breakdown">
                  <div className="ai-ins-charts">
                    {board.sections.map((section) => (
                      <figure key={section.id} className="ai-ins-chart">
                        <AssistantVisual result={section} requested={section.suggested_visual} />
                        {section.hint ? <figcaption>{section.hint}</figcaption> : null}
                      </figure>
                    ))}
                  </div>
                </Section>
              ) : null}

              {board.truncated ? <p className="ai-ins-note">Lists were capped at the newest records, so some counts may be partial.</p> : null}
            </div>
          ) : null}
        </div>

        <footer className="ai-ins-foot">
          <p className="ai-ins-disclaimer">Numbers come from your workspace. The summary is AI-written; verify before acting and re-run checks after a change.</p>
          <div className="ai-ins-foot-actions">
            <Button size="sm" variant="ghost" onClick={insights.reload} disabled={insights.phase === 'loading'} loading={insights.refreshing} loadingText="Refreshing">
              <RefreshCw size={14} aria-hidden="true" />Refresh
            </Button>
            <Button size="sm" onClick={askInChat}>
              <MessageSquareText size={14} aria-hidden="true" />Ask AI about this
            </Button>
          </div>
        </footer>
      </div>
    </dialog>
  );
}
