import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { useId } from 'react';
import { cn } from '../../lib/utils';
import { AnchorButton, Button } from './button';
import './primitives.css';

export type EmptyStateVariant = 'default' | 'skeleton';

type EmptyStateProps = {
  icon: LucideIcon;
  title: string;
  body: string;
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
  /** Visual weight of the generated action. Secondary keeps empty states calm by default. */
  actionVariant?: 'default' | 'secondary';
  /** Extra actions rendered after the primary one (e.g. a docs link). */
  actions?: ReactNode;
  variant?: EmptyStateVariant;
  className?: string;
};

function EmptyStateAction({
  actionLabel,
  actionHref,
  onAction,
  actionVariant
}: {
  actionLabel: string;
  actionHref?: string;
  onAction?: () => void;
  actionVariant: 'default' | 'secondary';
}) {
  if (actionHref) {
    return (
      <AnchorButton href={actionHref} variant={actionVariant}>
        {actionLabel}
      </AnchorButton>
    );
  }
  if (onAction) {
    return (
      <Button type="button" variant={actionVariant} onClick={onAction}>
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
  actionVariant = 'secondary',
  actions,
  variant = 'default',
  className
}: EmptyStateProps) {
  const titleId = useId();
  const showAction = Boolean(actionLabel && (actionHref || onAction));
  const normalizeCopy = (value: string) => value.trim().toLocaleLowerCase().replace(/[.!?]+$/, '');
  const showBody = Boolean(body.trim()) && normalizeCopy(body) !== normalizeCopy(title);
  const hasActions = showAction || Boolean(actions);

  return (
    <div
      data-ui="empty-state"
      className={cn('empty-state', variant === 'skeleton' && 'empty-state-skeleton', className)}
      role="region"
      aria-labelledby={titleId}
    >
      {variant === 'skeleton' ? (
        <div className="skeleton empty-state-visual" aria-hidden="true" />
      ) : (
        <Icon className="empty-icon" size={36} aria-hidden="true" />
      )}
      <h2 id={titleId}>{title}</h2>
      {showBody ? <p>{body}</p> : null}
      {hasActions ? (
        <div className="empty-state-actions">
          {showAction ? (
            <EmptyStateAction
              actionLabel={actionLabel!}
              actionHref={actionHref}
              onAction={onAction}
              actionVariant={actionVariant}
            />
          ) : null}
          {actions}
        </div>
      ) : null}
    </div>
  );
}
