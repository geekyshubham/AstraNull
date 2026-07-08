import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const BUTTON_STYLES_ID = 'ui-button-primitive-styles';

const buttonPrimitiveStyles = `
[data-ui='button'].btn {
  font-family: var(--font-body);
  cursor: pointer;
}
[data-ui='button'].btn:focus-visible {
  outline: none;
  box-shadow: var(--focus-ring);
}
[data-ui='button'].btn-default:hover:not(:disabled) {
  background: var(--fg);
  color: var(--bg);
  border-color: var(--fg);
  box-shadow: 0 0 0 4px color-mix(in oklab, var(--fg), transparent 82%);
}
[data-ui='button'].btn-default:active:not(:disabled) {
  background: var(--fg);
  color: var(--bg);
  border-color: var(--fg);
}
[data-ui='button'].btn-danger {
  border-color: color-mix(in oklab, var(--danger), var(--bg) 18%);
  background: color-mix(in oklab, var(--danger), var(--bg) 18%);
}
[data-ui='button'].btn-danger:hover:not(:disabled) {
  background: color-mix(in oklab, var(--danger), var(--fg) 8%);
  border-color: color-mix(in oklab, var(--danger), var(--fg) 8%);
}
[data-ui='button'].btn-danger:active:not(:disabled) {
  background: color-mix(in oklab, var(--danger), var(--bg) 10%);
  border-color: color-mix(in oklab, var(--danger), var(--bg) 10%);
}
@media (prefers-reduced-motion: reduce) {
  [data-ui='button'].btn {
    transition: none;
  }
  [data-ui='button'].btn:active:not(:disabled) {
    transform: none;
  }
}
`;

function ensureButtonStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(BUTTON_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = BUTTON_STYLES_ID;
  node.textContent = buttonPrimitiveStyles;
  document.head.appendChild(node);
}

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
  };

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, disabled, children, type = 'button', ...props }, ref) => {
    ensureButtonStyles();

    return (
      <button
        ref={ref}
        type={type}
        data-ui="button"
        className={cn(buttonVariants({ variant, size }), loading && 'btn-loading', className)}
        disabled={disabled || loading}
        aria-busy={loading || undefined}
        aria-disabled={disabled || loading ? true : undefined}
        {...props}
      >
        {loading ? <span className="spinner btn-inline-spinner" aria-hidden="true" /> : null}
        {loading ? <span className="sr-only">Loading</span> : null}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';

export type AnchorButtonProps = React.AnchorHTMLAttributes<HTMLAnchorElement> &
  VariantProps<typeof buttonVariants> & {
    disabled?: boolean;
  };

export const AnchorButton = React.forwardRef<HTMLAnchorElement, AnchorButtonProps>(
  ({ className, variant, size, disabled, tabIndex, onClick, ...props }, ref) => {
    ensureButtonStyles();

    return (
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
    );
  }
);

AnchorButton.displayName = 'AnchorButton';