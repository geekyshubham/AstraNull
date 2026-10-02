import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';
import './primitives.css';

const buttonVariants = cva('btn', {
  variants: {
    variant: {
      default: 'btn-default',
      secondary: 'btn-secondary',
      ghost: 'btn-ghost',
      danger: 'btn-danger'
    },
    size: {
      default: '',
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
  VariantProps<typeof buttonVariants> & {
    loading?: boolean;
    /**
     * Visible label while `loading` (e.g. "Saving…"). When omitted the original
     * label stays visible beside the spinner, so the button never changes width.
     */
    loadingText?: string;
  };

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, loadingText, disabled, children, type = 'button', ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      data-ui="button"
      data-loading={loading ? 'true' : undefined}
      className={cn(buttonVariants({ variant, size }), loading && 'btn-loading', className)}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      aria-disabled={disabled || loading ? true : undefined}
      {...props}
    >
      {loading ? <span className="spinner btn-inline-spinner" aria-hidden="true" /> : null}
      {loading && !loadingText ? <span className="sr-only">Loading</span> : null}
      {loading && loadingText ? loadingText : children}
    </button>
  )
);

Button.displayName = 'Button';

export type AnchorButtonProps = React.AnchorHTMLAttributes<HTMLAnchorElement> &
  VariantProps<typeof buttonVariants> & {
    disabled?: boolean;
  };

export const AnchorButton = React.forwardRef<HTMLAnchorElement, AnchorButtonProps>(
  ({ className, variant, size, disabled, tabIndex, onClick, ...props }, ref) => (
    <a
      ref={ref}
      data-ui="button"
      className={cn(buttonVariants({ variant, size }), disabled && 'is-locked', className)}
      aria-disabled={disabled || undefined}
      tabIndex={disabled ? -1 : tabIndex}
      onClick={
        disabled
          ? (event) => {
              event.preventDefault();
            }
          : onClick
      }
      {...props}
    />
  )
);

AnchorButton.displayName = 'AnchorButton';
