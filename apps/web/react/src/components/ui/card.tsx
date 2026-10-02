import * as React from 'react';
import { cn } from '../../lib/utils';
import './primitives.css';

export type CardProps = React.HTMLAttributes<HTMLDivElement> & {
  density?: 'default' | 'compact';
  /** Slightly elevated surface; uses the shared theme elevation tokens. */
  raised?: boolean;
  /** The whole card navigates or opens something, so it may respond to hover and press. */
  interactive?: boolean;
};

export function Card({ className, density = 'default', raised = false, interactive = false, ...props }: CardProps) {
  return (
    <div
      data-ui="card"
      data-interactive={interactive ? 'true' : undefined}
      className={cn(
        'card',
        density === 'compact' && 'card-compact',
        raised && 'card-raised',
        interactive && 'card-interactive',
        className
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card-header', className)} {...props} />;
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={cn('card-title', className)} {...props} />;
}

export function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('card-description', className)} {...props} />;
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card-content', className)} {...props} />;
}

export function CardFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card-footer', className)} {...props} />;
}
