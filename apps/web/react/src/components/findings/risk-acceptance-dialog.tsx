import { useEffect, useId, useState } from 'react';
import { ConfirmModal } from '../../lib/crud-ui';
import './risk-acceptance-dialog.css';

export const RISK_ACCEPTANCE_REASON_MIN = 20;
export const RISK_ACCEPTANCE_REASON_MAX = 2000;
const RISK_ACCEPTANCE_MAX_REVIEW_DAYS = 365;
const DAY_MS = 24 * 60 * 60 * 1000;
const REVIEW_PRESETS = [30, 90, 180] as const;

export type RiskAcceptanceInput = { reason: string; review_at: string };

type ReviewChoice = `${(typeof REVIEW_PRESETS)[number]}` | 'custom';

function isoDay(ms: number) {
  const date = new Date(ms);
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

/** Review instant for a choice, or null when the custom date is missing or out of range. */
export function riskReviewAt(choice: ReviewChoice, customDay: string, now = Date.now()): string | null {
  const ms = choice === 'custom'
    ? (/^\d{4}-\d{2}-\d{2}$/.test(customDay) ? new Date(`${customDay}T12:00:00`).getTime() : Number.NaN)
    : now + Number(choice) * DAY_MS;
  if (!Number.isFinite(ms) || ms <= now || ms > now + RISK_ACCEPTANCE_MAX_REVIEW_DAYS * DAY_MS) return null;
  return new Date(ms).toISOString();
}

/**
 * Risk acceptance is a dated, reasoned decision: a written justification and a review date,
 * recorded with the accepting user and time by the server. It never reads as a fix.
 */
export function RiskAcceptanceDialog({
  open,
  busy,
  findingCount = 1,
  onCancel,
  onConfirm
}: {
  open: boolean;
  busy: boolean;
  findingCount?: number;
  onCancel: () => void;
  onConfirm: (input: RiskAcceptanceInput) => void;
}) {
  const reasonId = useId();
  const reasonHintId = useId();
  const reasonErrorId = useId();
  const reviewId = useId();
  const customId = useId();
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const [review, setReview] = useState<ReviewChoice>('90');
  const [customDay, setCustomDay] = useState('');

  useEffect(() => {
    if (open) return;
    setReason('');
    setTouched(false);
    setReview('90');
    setCustomDay('');
  }, [open]);

  const trimmed = reason.trim();
  const reasonError = trimmed.length < RISK_ACCEPTANCE_REASON_MIN
    ? `Write at least ${RISK_ACCEPTANCE_REASON_MIN} characters (${trimmed.length} so far).`
    : trimmed.length > RISK_ACCEPTANCE_REASON_MAX
      ? `Keep the justification to ${RISK_ACCEPTANCE_REASON_MAX} characters.`
      : '';
  const reviewAt = riskReviewAt(review, customDay);
  const now = Date.now();
  const showReasonError = touched && Boolean(reasonError);

  return (
    <ConfirmModal
      open={open}
      title={findingCount > 1 ? `Accept risk for ${findingCount} findings` : 'Accept risk for this finding'}
      confirmLabel="Accept risk"
      confirmTone="danger"
      busy={busy}
      confirmDisabled={Boolean(reasonError) || !reviewAt}
      onCancel={onCancel}
      onConfirm={() => {
        if (reasonError || !reviewAt) {
          setTouched(true);
          return;
        }
        onConfirm({ reason: trimmed, review_at: reviewAt });
      }}
      description={(
        <div className="stack-tight risk-acceptance-form">
          <p>
            Accepting risk records a decision, not a fix. The {findingCount > 1 ? 'findings stay' : 'finding stays'} visible with {findingCount > 1 ? 'their' : 'its'} evidence until the review date, and the server records who accepted it and when.
            {findingCount > 1 ? ' The same justification and review date are applied to each finding.' : ''}
          </p>
          <label className="field full" htmlFor={reasonId}>
            <span>Justification</span>
            <textarea
              id={reasonId}
              value={reason}
              rows={4}
              maxLength={RISK_ACCEPTANCE_REASON_MAX + 200}
              required
              aria-required="true"
              aria-invalid={showReasonError || undefined}
              aria-describedby={showReasonError ? `${reasonHintId} ${reasonErrorId}` : reasonHintId}
              disabled={busy}
              placeholder="Why the risk is acceptable for now, and any compensating control."
              onChange={(event) => setReason(event.target.value)}
              onBlur={() => setTouched(true)}
            />
            <span id={reasonHintId} className="muted small">Required. At least {RISK_ACCEPTANCE_REASON_MIN} characters.</span>
            {showReasonError ? <span id={reasonErrorId} className="field-error small" role="alert">{reasonError}</span> : null}
          </label>
          <label className="field full" htmlFor={reviewId}>
            <span>Review by</span>
            <select id={reviewId} className="input" value={review} disabled={busy} onChange={(event) => setReview(event.target.value as ReviewChoice)}>
              {REVIEW_PRESETS.map((days) => <option key={days} value={String(days)}>In {days} days</option>)}
              <option value="custom">Choose a date</option>
            </select>
          </label>
          {review === 'custom' ? (
            <label className="field full" htmlFor={customId}>
              <span>Review date</span>
              <input
                id={customId}
                className="input"
                type="date"
                value={customDay}
                min={isoDay(now + DAY_MS)}
                max={isoDay(now + (RISK_ACCEPTANCE_MAX_REVIEW_DAYS - 1) * DAY_MS)}
                required
                aria-required="true"
                disabled={busy}
                onChange={(event) => setCustomDay(event.target.value)}
              />
              <span className="muted small">Within the next {RISK_ACCEPTANCE_MAX_REVIEW_DAYS} days.</span>
            </label>
          ) : null}
          {reviewAt ? <p className="muted small">Review due {new Date(reviewAt).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}.</p> : null}
        </div>
      )}
    />
  );
}
