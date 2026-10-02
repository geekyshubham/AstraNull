/**
 * Notification channels panel styles (token-only).
 *
 * Neutral colors, spacing, radii, motion, and focus come from the design tokens in styles.css
 * `:root`. The only literal colors are the third-party brand tokens below (`--brand-slack-*`,
 * `--brand-teams-*`), written in OKLCH as exact conversions of Slack's published brand colors and
 * the fills in Microsoft's official Teams product icon. They are scoped to `.channel-logo` so they
 * cannot leak into the product palette. No hex literals appear in this file.
 *
 * The channel cards, logo well, chips, and footer use the shared INTEGRATION_TILE_STYLES sheet
 * (integration-tile-styles.ts), the same one the DNS/edge provider directory uses. This file only
 * holds the brand tokens and the panel-specific heading, table cells, and connect dialog.
 */
export const NOTIFICATION_CHANNELS_STYLES = `
.channel-logo {
  --brand-slack-red: oklch(58.80% 0.2216 11.49);
  --brand-slack-blue: oklch(76.80% 0.1305 223.20);
  --brand-slack-green: oklch(69.11% 0.1422 160.24);
  --brand-slack-yellow: oklch(79.66% 0.1517 82.65);
  --brand-teams-tile-1: oklch(53.91% 0.1492 276.62);
  --brand-teams-tile-2: oklch(50.09% 0.1611 275.62);
  --brand-teams-tile-3: oklch(43.42% 0.1684 274.11);
  --brand-teams-deep: oklch(51.94% 0.1717 275.23);
  --brand-teams-light: oklch(65.11% 0.1536 277.91);
  --brand-teams-glyph: oklch(100% 0 0);
  --brand-teams-shade: oklch(0% 0 0);
}
.channel-logo .channel-mark {
  width: 56%;
  height: 56%;
  display: block;
}
.channel-logo .channel-glyph {
  width: 50%;
  height: 50%;
}
.channel-logo[data-channel='email'] .channel-glyph { color: var(--accent); }
.channel-logo[data-channel='webhook'] .channel-glyph { color: var(--fg); }
.channel-logo .slack-red { fill: var(--brand-slack-red); }
.channel-logo .slack-blue { fill: var(--brand-slack-blue); }
.channel-logo .slack-green { fill: var(--brand-slack-green); }
.channel-logo .slack-yellow { fill: var(--brand-slack-yellow); }
.channel-logo .teams-stop-1 { stop-color: var(--brand-teams-tile-1); }
.channel-logo .teams-stop-2 { stop-color: var(--brand-teams-tile-2); }
.channel-logo .teams-stop-3 { stop-color: var(--brand-teams-tile-3); }
.channel-logo .teams-deep { fill: var(--brand-teams-deep); }
.channel-logo .teams-light { fill: var(--brand-teams-light); }
.channel-logo .teams-shade { fill: var(--brand-teams-shade); }
.channel-logo .teams-glyph { fill: var(--brand-teams-glyph); }

.notification-channels {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-4);
}
.notification-channels .nc-heading {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: var(--space-3);
}
.notification-channels .nc-heading h2 {
  margin: 0;
  color: var(--fg);
  text-wrap: balance;
}
.notification-channels .nc-heading h2:focus:not(:focus-visible) {
  outline: none;
}
.notification-channels .nc-heading p {
  max-width: 72ch;
  margin: var(--space-1) 0 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.5;
}
.notification-channels .nc-channel-cell {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-2);
  color: var(--fg);
}
.notification-channels .nc-preview {
  color: var(--fg-2);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  overflow-wrap: anywhere;
}
.notification-channels .nc-events {
  color: var(--fg-2);
  font-size: var(--text-sm);
}
.notification-channels .nc-footnote {
  margin: 0;
  color: var(--muted);
  font-size: var(--text-xs);
}
.notification-channels .nc-row-actions {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 4px;
}

.notification-channels .nc-loading {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.nc-dialog-body {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}
.nc-setup h4,
.nc-form-title {
  margin: 0 0 var(--space-2);
  color: var(--fg);
  font-size: var(--text-sm);
  font-weight: 600;
}
.nc-steps {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  margin: 0;
  padding-left: var(--space-5);
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.55;
}
.nc-steps li::marker {
  color: var(--muted);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
}
.nc-steps strong { color: var(--fg); font-weight: 600; }
.nc-steps code,
.nc-note code {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
}
.nc-note {
  margin: var(--space-3) 0 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.5;
}
.nc-docs-link {
  display: inline-flex;
  min-height: 44px;
  align-items: center;
  gap: var(--space-1);
  color: var(--fg);
  font-size: var(--text-sm);
  text-decoration: underline;
  text-underline-offset: 3px;
}
.nc-docs-link:hover { color: var(--accent); }
.nc-docs-link:focus-visible {
  border-radius: var(--radius-sm);
  outline: none;
  box-shadow: var(--focus-ring);
}
.nc-field-hint {
  margin: 0;
  color: var(--muted);
  font-size: var(--text-xs);
  line-height: 1.45;
}
.nc-field-error {
  margin: 0;
  color: var(--danger);
  font-size: var(--text-sm);
}
.nc-field-warning {
  margin: 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
}
.nc-form input[aria-invalid='true'] {
  border-color: var(--danger);
}
.nc-payload {
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--proof-surface);
}
.nc-payload > summary {
  display: flex;
  min-height: 44px;
  align-items: center;
  padding: 0 var(--space-3);
  color: var(--fg);
  font-size: var(--text-sm);
  cursor: pointer;
}
.nc-payload > summary:focus-visible {
  border-radius: var(--radius-md);
  outline: none;
  box-shadow: var(--focus-ring);
}
.nc-payload pre {
  max-height: 260px;
  margin: 0;
  padding: var(--space-3);
  overflow: auto;
  border-top: 1px solid var(--border-soft);
  color: var(--fg-2);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  line-height: 1.5;
}

@media (pointer: coarse) {
  .notification-channels .btn,
  .nc-dialog-body .btn {
    min-height: 44px;
  }
}
`;
