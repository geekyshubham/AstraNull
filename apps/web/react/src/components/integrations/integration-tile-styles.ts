/**
 * Shared integration tile styles (token-only).
 *
 * One visual language for every integration card on /app#integrations: DNS/edge provider cards
 * and notification channel cards (Slack, Microsoft Teams, Email, Webhook) use the same tile,
 * neutral logo well, status chip, footer, and button treatment. Colors come exclusively from the
 * design tokens in styles.css `:root`; no raw hex appears here.
 *
 * The logo well stays neutral because the marks it holds are full-color: white in the light theme
 * and a soft gray mixed from tokens in the default dark theme. No per-brand tint is applied.
 *
 * Selectors are unscoped `integration-*` classes so the notification panel renders correctly
 * whether or not it is mounted inside `.integration-page`. Injecting this sheet more than once is
 * harmless because the rules are identical.
 */
export const INTEGRATION_TILE_STYLES = `
.integration-tile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr));
  gap: var(--space-3);
  margin: 0;
  padding: 0;
  list-style: none;
}
.integration-tile {
  display: flex;
  min-width: 0;
  min-height: 100%;
  flex-direction: column;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  background: var(--proof-surface);
  transition: border-color var(--motion-fast) var(--motion-ease), background var(--motion-fast) var(--motion-ease);
}
.integration-tile:hover,
.integration-tile:focus-within {
  border-color: var(--border-strong);
  background: var(--surface-raised);
}
.integration-tile[data-connected] {
  border-color: color-mix(in oklab, var(--success), transparent 55%);
}
.integration-tile-head,
.integration-tile-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
}
.integration-identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-3);
}
.integration-logo-well {
  display: grid;
  width: var(--space-10);
  height: var(--space-10);
  flex: 0 0 var(--space-10);
  place-items: center;
  overflow: hidden;
  border-radius: var(--radius-md);
  background: color-mix(in oklab, var(--fg) 12%, var(--surface));
  box-shadow: inset 0 0 0 1px var(--border-soft);
  color: var(--fg-2);
}
.integration-logo-well-sm {
  width: var(--space-6);
  height: var(--space-6);
  flex-basis: var(--space-6);
  border-radius: var(--radius-sm);
}
:root[data-theme='light'] .integration-logo-well {
  background: var(--surface);
}
.integration-logo-well > img,
.integration-logo-well > svg {
  display: block;
}
.integration-tile-name {
  min-width: 0;
}
.integration-tile-name strong {
  display: block;
  color: var(--fg);
  font-size: var(--text-sm);
  font-weight: 600;
  overflow-wrap: anywhere;
}
.integration-tile-name span {
  color: var(--muted);
  font-size: var(--text-xs);
}
.integration-tile-desc {
  flex: 1;
  margin: 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.5;
}
.integration-tile-footer {
  flex-wrap: wrap;
  margin-top: auto;
  padding-top: var(--space-3);
  border-top: 1px solid var(--border-soft);
}
.integration-tile-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: var(--space-2);
}
.integration-chip {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-pill);
  font-size: var(--text-xs);
  font-weight: 600;
  white-space: nowrap;
}
.integration-chip[data-tone='positive'] {
  background: color-mix(in oklab, var(--success), transparent 86%);
  color: var(--success);
}
/* Light theme: match .badge-success so 12px chip text clears WCAG AA 4.5:1 on the pale tint. */
:root[data-theme='light'] .integration-chip[data-tone='positive'] {
  color: color-mix(in oklab, var(--success), var(--fg) 35%);
}
.integration-chip[data-tone='neutral'] {
  background: var(--surface-sunk);
  box-shadow: inset 0 0 0 1px var(--border-soft);
  color: var(--fg-2);
}
.integration-tile .btn {
  min-height: 44px;
  transition: background var(--motion-fast) var(--motion-ease), border-color var(--motion-fast) var(--motion-ease), color var(--motion-fast) var(--motion-ease), transform var(--motion-fast) var(--motion-ease);
}
.integration-tile .btn:active:not(:disabled) {
  transform: scale(var(--press-scale));
}
.integration-tile .btn:focus-visible {
  outline: none;
  box-shadow: var(--focus-ring);
}
.integration-tally {
  color: var(--muted);
  font-size: var(--text-xs);
  white-space: nowrap;
}
@media (max-width: 640px) {
  .integration-tile-footer {
    align-items: flex-start;
    flex-direction: column;
  }
  .integration-tile-actions {
    width: 100%;
  }
  .integration-tile-actions .btn {
    flex: 1 1 0;
  }
}
@media (prefers-reduced-motion: reduce) {
  .integration-tile,
  .integration-tile .btn {
    transition: none;
  }
  .integration-tile .btn:active:not(:disabled) {
    transform: none;
  }
}
`;
