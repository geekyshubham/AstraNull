import { useEffect, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { assistantAvailable, useAssistantStatus } from '../../lib/assistant-api';
import { usePublishedInsightScope } from '../../lib/assistant-insights-api';
import { currentInsightScope, sanitizeScope, type InsightScope } from '../../lib/assistant-insights.mjs';
import type { PortalConfig, Session } from '../../lib/types';
import { cn } from '../../lib/utils';
import { InsightsDialog } from './insights-dialog';

function useRouteScope(enabled: boolean) {
  const published = usePublishedInsightScope();
  const [hash, setHash] = useState(() => (typeof window === 'undefined' ? '' : window.location.hash));
  useEffect(() => {
    if (!enabled) return undefined;
    const update = () => setHash(window.location.hash);
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, [enabled]);
  return enabled ? currentInsightScope(hash, published) : null;
}

/**
 * Opens AI insights. Without a scope it follows the open page (the topbar entry); with one it
 * analyses that record (inline entries in detail views).
 */
export function AiInsightsButton({ config, session, scope, variant = 'inline', label = 'AI insights', className }: {
  config: PortalConfig;
  session: Session;
  scope?: InsightScope | null;
  variant?: 'topbar' | 'inline';
  label?: string;
  className?: string;
}) {
  const { status } = useAssistantStatus(config, session);
  const allowed = session.principal !== 'staff' && assistantAvailable(status);
  const routeScope = useRouteScope(allowed && scope === undefined);
  const resolved = scope === undefined ? routeScope : sanitizeScope(scope);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState<InsightScope | null>(null);
  if (!allowed || !resolved) return null;
  return (
    <>
      <button
        type="button"
        className={cn('ai-ins-trigger', `ai-ins-trigger-${variant}`, className)}
        aria-haspopup="dialog"
        aria-expanded={open}
        title={`AI insights for this ${resolved.label.toLowerCase()}`}
        onClick={() => {
          setActive(resolved);
          setOpen(true);
        }}
      >
        <span className="ai-ins-trigger-mark" aria-hidden="true"><Sparkles size={14} /></span>
        <span className="ai-ins-trigger-label">{label}</span>
      </button>
      {active ? <InsightsDialog config={config} session={session} scope={active} open={open} onClose={() => setOpen(false)} /> : null}
    </>
  );
}
