import type { LucideIcon } from 'lucide-react';
import { useId } from 'react';
import { cn } from '../../lib/utils';
import { AnchorButton, Button } from './button';

export type EmptyStateVariant = 'default' | 'skeleton';

type EmptyStateProps = {
  icon: LucideIcon;
  title: string;
  body: string;
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
  variant?: EmptyStateVariant;
};

function EmptyStateAction({
  actionLabel,
  actionHref,
  onAction
}: {
  actionLabel: string;
  actionHref?: string;
  onAction?: () => void;
}) {
  if (actionHref) {
    return (
      <AnchorButton href={actionHref} variant="secondary">
        {actionLabel}
      </AnchorButton>
    );
  }
  if (onAction) {
    return (
      <Button type="button" variant="secondary" onClick={onAction}>
        {actionLabel}
      </Button>
    );
  }
  return null;
}

export function EmptyState({
  icon: Icon,
  title,
  body,
  actionLabel,
  actionHref,
  onAction,
  variant = 'default'
}: EmptyStateProps) {
  const titleId = useId();
  const showAction = Boolean(actionLabel && (actionHref || onAction));

  return (
    <div
      className={cn('empty-state', variant === 'skeleton' && 'empty-state-skeleton')}
      role="region"
      aria-labelledby={titleId}
    >
      {variant === 'skeleton' ? (
        <div className="skeleton empty-state-visual" aria-hidden="true" />
      ) : (
        <Icon className="empty-icon" size={36} aria-hidden="true" />
      )}
      <h2 id={titleId}>{title}</h2>
      <p>{body}</p>
      {showAction ? (
        <EmptyStateAction actionLabel={actionLabel!} actionHref={actionHref} onAction={onAction} />
      ) : null}
    </div>
  );
}