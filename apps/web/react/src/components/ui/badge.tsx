import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const badgeVariants = cva('badge', {
  variants: {
    tone: {
      default: 'badge-default',
      success: 'badge-success',
      warn: 'badge-warn',
      danger: 'badge-danger',
      info: 'badge-info',
      muted: 'badge-muted'
    }
  },
  defaultVariants: {
    tone: 'default'
  }
});

export type BadgeProps = React.HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants> & {
    /**
     * When true, uses mono typography (ID-style chips). Default false uses sans label styling.
     * Optional leading icons: pass as children; prefer Lucide at size 12 with default stroke.
     */
    mono?: boolean;
  };

export function Badge({ className, tone, mono = false, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), !mono && 'badge-sans', className)} {...props} />;
}