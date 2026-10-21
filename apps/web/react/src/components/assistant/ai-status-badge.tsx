import { Sparkles } from 'lucide-react';
import './ai-motion.css';

/** One badge for every AI surface: writing (with seconds), AI-written, or computed. */
export function AiStatusBadge({ pending, ai, seconds, pendingLabel = 'Writing' }: { pending: boolean; ai: boolean; seconds?: number; pendingLabel?: string }) {
  if (pending) {
    return (
      <span className="ai-badge is-pending" aria-live="off">
        <span className="ai-pulse" aria-hidden="true" />{pendingLabel}… {seconds ?? 0}s
      </span>
    );
  }
  if (ai) {
    return <span className="ai-badge is-ai"><Sparkles size={12} aria-hidden="true" />AI-written</span>;
  }
  return <span className="ai-badge">Computed</span>;
}
