import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const buttonVariants = cva('btn', {
  variants: {
    variant: {
      default: 'btn-default',
      secondary: 'btn-secondary',
      ghost: 'btn-ghost',
      danger: 'btn-danger'
    },
    size: {
      default: 'btn-md',
      sm: 'btn-sm',
      icon: 'btn-icon'
    }
  },
  defaultVariants: {
    variant: 'default',
    size: 'default'
  }
});

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants>;

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  )
);

Button.displayName = 'Button';

export type AnchorButtonProps = React.AnchorHTMLAttributes<HTMLAnchorElement> &
  VariantProps<typeof buttonVariants>;

export function AnchorButton({ className, variant, size, ...props }: AnchorButtonProps) {
  return <a className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
