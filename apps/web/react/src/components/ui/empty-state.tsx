import type { LucideIcon } from 'lucide-react';
import { AnchorButton } from './button';

type EmptyStateProps = {
  icon: LucideIcon;
  title: string;
  body: string;
  actionLabel?: string;
  actionHref?: string;
};

export function EmptyState({ icon: Icon, title, body, actionLabel, actionHref }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <Icon className="empty-icon" size={36} />
      <h3>{title}</h3>
      <p>{body}</p>
      {actionLabel && actionHref ? (
        <AnchorButton href={actionHref} variant="secondary" size="sm">
          {actionLabel}
        </AnchorButton>
      ) : null}
    </div>
  );
}
