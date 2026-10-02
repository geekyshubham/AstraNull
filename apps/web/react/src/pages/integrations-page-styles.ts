/**
 * Integrations page styles (token-only).
 *
 * Colors come exclusively from the design tokens defined in styles.css `:root`.
 * The provider and notification channel tiles (card, neutral logo well, chip,
 * footer, buttons) share one sheet, INTEGRATION_TILE_STYLES in
 * components/integrations/integration-tile-styles.ts, so both card families stay
 * visually identical. This file holds page-only layout: the directory header,
 * setup guides, the configure flow, and the single-domain result.
 * No per-provider tint is applied and no raw hex appears here.
 */
export const INTEGRATIONS_PAGE_STYLES = `
.integration-page .integration-directory-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: var(--space-1);
}
.integration-page .provider-directory-footnote {
  margin: var(--space-3) 0 0;
}
.integration-page .provider-guide {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}
.integration-page .provider-guide-facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
  gap: var(--space-3);
  margin: 0;
}
.integration-page .provider-guide-facts > div {
  min-width: 0;
  padding: var(--space-3);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--surface-sunk);
}
.integration-page .provider-guide-facts dt {
  margin-bottom: var(--space-1);
  color: var(--muted);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-caps);
}
.integration-page .provider-guide-facts dd {
  margin: 0;
  color: var(--fg);
  font-size: var(--text-sm);
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.integration-page .provider-guide-facts code {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
}
.integration-page .provider-guide-section h3 {
  margin: 0 0 var(--space-2);
  color: var(--fg);
  font-size: var(--text-sm);
}
.integration-page .provider-guide-section p {
  margin: 0;
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.55;
}
.integration-page .provider-guide-steps {
  display: grid;
  gap: var(--space-2);
  margin: 0;
  padding-left: var(--space-5);
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.55;
}
.integration-page .provider-guide-links {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2) var(--space-4);
  margin: 0;
  padding: 0;
  list-style: none;
}
.integration-page .provider-guide-links a {
  display: inline-flex;
  min-height: 44px;
  align-items: center;
  gap: var(--space-1);
  color: var(--accent);
  font-size: var(--text-sm);
  text-decoration: underline;
  text-underline-offset: 3px;
}
.integration-page .provider-guide-links a:hover {
  color: var(--accent-hover);
}
.integration-page .provider-guide-links a:focus-visible {
  outline: none;
  box-shadow: var(--focus-ring);
  border-radius: var(--radius-sm);
}
.integration-page .provider-flow-guide {
  margin-top: var(--space-4);
}
.integration-page .provider-flow-guide > summary {
  display: flex;
  min-height: 44px;
  align-items: center;
  gap: var(--space-2);
}
.integration-page .provider-scope-hint {
  display: flex;
  align-items: flex-start;
  gap: var(--space-2);
  padding: var(--space-3);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  background: var(--surface-sunk);
  color: var(--fg-2);
  font-size: var(--text-sm);
  line-height: 1.5;
}
.integration-page .provider-scope-hint svg {
  flex: none;
  margin-top: var(--space-0-5);
  color: var(--accent);
}
.integration-page .integration-directory-heading,
.integration-page .provider-flow-context,
.integration-page .domain-result-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
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
  .integration-page .provider-flow-context,
  .integration-page .domain-result-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .integration-page .provider-flow-context label {
    width: 100%;
  }
  .integration-page .integration-directory-meta {
    align-items: flex-start;
  }
}
`;
