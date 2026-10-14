import { NOT_TESTED_DETAIL, requiredInputMissingHref, type RequiredInputMissing } from '../../lib/missing-input.mjs';
import { Badge } from '../ui/badge';
import { AnchorButton } from '../ui/button';
import './runs-components.css';

/** Neutral note for a run that finished without sending anything because a check input was missing. */
export function NotTestedNote({ info, targetId = '', showLabel = true }: { info: RequiredInputMissing; targetId?: string; showLabel?: boolean }) {
  const href = requiredInputMissingHref(info, targetId);
  return (
    <div className="not-tested-note" role="note" data-label={showLabel || undefined}>
      {showLabel ? <Badge tone="muted">{info.label}</Badge> : null}
      <div className="not-tested-note-body">
        <p>{info.message}</p>
        {info.serverMessage ? <p className="not-tested-note-detail">{NOT_TESTED_DETAIL}</p> : null}
        {href && info.cta ? <AnchorButton size="sm" variant="secondary" href={href}>{info.cta}</AnchorButton> : null}
      </div>
    </div>
  );
}

/** Compact table form: the neutral label, with the plain reason as its title. */
export function NotTestedBadge({ info }: { info: RequiredInputMissing }) {
  return <Badge tone="muted" title={info.message}>{info.label}</Badge>;
}
