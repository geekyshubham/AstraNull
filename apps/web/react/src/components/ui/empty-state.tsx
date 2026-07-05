import type { LucideIcon } from 'lucide-react';
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

export function EmptyState({
  icon: Icon,
  title,
  body,
  actionLabel,
  actionHref,
  onAction,
  variant = 'default'
}: EmptyStateProps) {
  const showHrefAction = Boolean(actionLabel && actionHref);
  const showClickAction = Boolean(actionLabel && onAction && !actionHref);

  return (
    <div className={cn('empty-state', variant === 'skeleton' && 'empty-state-skeleton')}>
      {variant === 'skeleton' ? (
        <div className="skeleton empty-state-visual" aria-hidden="true" />
      ) : (
        <Icon className="empty-icon" size={36} />
      )}
      <h2>{title}</h2>
      <p>{body}</p>
      {showClickAction ? (
        <Button type="button" variant="secondary" onClick={onAction}>
          {actionLabel}
        </Button>
      ) : null}
      {showHrefAction ? (
        <AnchorButton href={actionHref} variant="secondary">
          {actionLabel}
        </AnchorButton>
      ) : null}
    </div>
  );
}
