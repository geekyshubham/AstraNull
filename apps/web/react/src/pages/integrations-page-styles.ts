/**
 * Integrations page styles (token-only).
 *
 * Colors come exclusively from the design tokens defined in styles.css `:root`.
 * Provider brand marks render in `currentColor`; per-provider tints reuse the
 * existing accent/signal/status tokens via the `data-provider` selector so no
 * raw hex ever appears here (lint:portal only scans styles.css for hex, but we
 * keep this file hex-free by convention).
 */
export const INTEGRATIONS_PAGE_STYLES = `
.integration-page .provider-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr));
  gap: var(--space-3);
  margin: 0;
  padding: 0;
  list-style: none;
}
.integration-page .provider-card {
  display: flex;
  min-width: 0;
  min-height: 100%;
  flex-direction: column;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  background: var(--proof-surface);
  transition: border-color var(--motion-fast) var(--motion-ease), background var(--motion-fast) var(--motion-ease), box-shadow var(--motion-fast) var(--motion-ease);
}
.integration-page .provider-card:hover {
  border-color: var(--border-strong);
  background: var(--surface-raised);
  box-shadow: var(--elev-raised);
}
.integration-page .provider-card-head,
.integration-page .provider-card-footer,
.integration-page .integration-directory-heading,
.integration-page .provider-flow-context,
.integration-page .domain-result-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
}
.integration-page .provider-identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-3);
}
.integration-page .provider-logo-frame {
  display: grid;
  width: var(--space-10);
  height: var(--space-10);
  flex: 0 0 var(--space-10);
  place-items: center;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--surface);
  color: var(--fg-2);
}
/* Per-provider tint reuses existing status/accent tokens only. */
.integration-page .provider-logo-frame[data-provider='cloudflare'],
.integration-page .provider-logo-frame[data-provider='godaddy'],
.integration-page .provider-logo-frame[data-provider='route53'] {
  background: var(--warn-soft, color-mix(in oklab, var(--warn), transparent 88%));
  color: var(--warn);
}
.integration-page .provider-logo-frame[data-provider='akamai'],
.integration-page .provider-logo-frame[data-provider='azure'] {
  background: var(--accent-soft);
  color: var(--accent);
}
.integration-page .provider-logo-frame[data-provider='namecheap'],
.integration-page .provider-logo-frame[data-provider='ibm_ns1'] {
  background: var(--signal-soft);
  color: var(--signal);
}
.integration-page .provider-logo-frame[data-provider='google_cloud'],
.integration-page .provider-logo-frame[data-provider='hetzner'] {
  background: color-mix(in oklab, var(--success), transparent 88%);
  color: var(--success);
}
.integration-page .provider-name {
  min-width: 0;
}
.integration-page .provider-name strong {
  display: block;
  color: var(--fg);
  font-size: var(--text-sm);
  overflow-wrap: anywhere;
}
.integration-page .provider-name span {
  color: var(--muted);
  font-size: var(--text-xs);
}
.integration-page .provider-description {
  flex: 1;
  margin: 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.5;
}
.integration-page .provider-card-footer {
  margin-top: auto;
  padding-top: var(--space-2);
  border-top: 1px solid var(--border-soft);
}
.integration-page .connector-name-cell {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-2);
  color: var(--fg-2);
}
.integration-page .integration-directory-note {
  max-width: 72ch;
  margin: 0;
}
.integration-page .kpi-cell {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-1);
}
.integration-page .kpi-cell-label {
  color: var(--muted);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-caps);
}
.integration-page .kpi-cell-value {
  color: var(--fg);
  font-family: var(--font-mono);
  font-size: var(--text-xl);
}
.integration-page .kpi-cell-delta {
  color: var(--fg-2);
  font-size: var(--text-xs);
}
.integration-page .provider-flow-context {
  align-items: flex-end;
  margin-bottom: var(--space-4);
  padding-bottom: var(--space-4);
  border-bottom: 1px solid var(--border-soft);
}
.integration-page .provider-flow-context label {
  min-width: min(100%, 260px);
}
.integration-page .provider-path-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--space-3);
}
.integration-page .provider-path {
  display: flex;
  min-width: 0;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--space-4);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  background: var(--proof-surface);
}
.integration-page .provider-path-icon {
  display: grid;
  width: var(--space-10);
  height: var(--space-10);
  place-items: center;
  border-radius: var(--radius-md);
  background: var(--accent-soft);
  color: var(--accent);
}
.integration-page .provider-path h3,
.integration-page .provider-path p {
  margin: 0;
}
.integration-page .provider-path h3 {
  color: var(--fg);
  font-size: var(--text-sm);
}
.integration-page .provider-path p {
  color: var(--fg-2);
  font-size: var(--text-xs);
  line-height: 1.55;
}
.integration-page .provider-path .btn {
  width: 100%;
  margin-top: auto;
}
.integration-page .domain-provenance,
.integration-page .domain-result {
  padding: var(--space-3);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--proof-surface);
}
.integration-page .domain-provenance {
  color: var(--fg-2);
  font-size: var(--text-xs);
  line-height: 1.5;
}
.integration-page .domain-result {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.integration-page .domain-result h3,
.integration-page .domain-result p {
  margin: 0;
}
.integration-page .domain-result h3 {
  color: var(--fg);
  font-size: var(--text-base);
}
.integration-page .domain-result p {
  color: var(--fg-2);
  font-size: var(--text-sm);
}
@media (max-width: 860px) {
  .integration-page .provider-path-grid {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 640px) {
  .integration-page .integration-directory-heading,
  .integration-page .provider-card-footer,
  .integration-page .provider-flow-context,
  .integration-page .domain-result-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .integration-page .provider-card-footer .btn,
  .integration-page .provider-flow-context label {
    width: 100%;
  }
}
@media (prefers-reduced-motion: reduce) {
  .integration-page .provider-card {
    transition: none;
  }
}
`;
