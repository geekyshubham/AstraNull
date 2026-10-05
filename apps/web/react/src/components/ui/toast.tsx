import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AlertCircle, CheckCircle2, Info, TriangleAlert, X } from 'lucide-react';
import { cn } from '../../lib/utils';

export type ToastTone = 'success' | 'warn' | 'error' | 'info';

export type ToastProps = {
  message: ReactNode;
  tone?: ToastTone;
  duration?: number;
  onDismiss?: () => void;
  className?: string;
};

export function Toast({
  message,
  tone = 'success',
  duration = 5000,
  onDismiss,
  className,
}: ToastProps) {
  const [exiting, setExiting] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const remainingRef = useRef(duration);
  const startTimeRef = useRef<number>(Date.now());
  const onDismissRef = useRef(onDismiss);
  onDismissRef.current = onDismiss;

  const triggerDismiss = () => {
    if (exiting || dismissed) return;
    setExiting(true);
    setTimeout(() => {
      setDismissed(true);
      onDismissRef.current?.();
    }, 150);
  };

  useEffect(() => {
    if (!message || duration <= 0) return;
    setExiting(false);
    setDismissed(false);
    remainingRef.current = duration;
    startTimeRef.current = Date.now();

    timerRef.current = setTimeout(() => {
      triggerDismiss();
    }, duration);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [message, duration]);

  const handleMouseEnter = () => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
      const elapsed = Date.now() - startTimeRef.current;
      remainingRef.current = Math.max(1000, remainingRef.current - elapsed);
    }
  };

  const handleMouseLeave = () => {
    if (!exiting && !timerRef.current && remainingRef.current > 0) {
      startTimeRef.current = Date.now();
      timerRef.current = setTimeout(() => {
        triggerDismiss();
      }, remainingRef.current);
    }
  };

  if (!message || dismissed) return null;

  const Icon =
    tone === 'error'
      ? TriangleAlert
      : tone === 'warn'
      ? AlertCircle
      : tone === 'info'
      ? Info
      : CheckCircle2;

  return (
    <div className="toast-region" aria-live="polite">
      <div
        className={cn('toast', `toast-${tone}`, exiting && 'toast-exit', className)}
        role="status"
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
      >
        <Icon size={16} aria-hidden="true" />
        <span className="toast-message">{message}</span>
        <button
          type="button"
          className="toast-close"
          onClick={triggerDismiss}
          aria-label="Dismiss notification"
        >
          <X size={14} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
