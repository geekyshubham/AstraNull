/**
 * Shared release-doc markdown fixtures for gate-parsing tests.
 *
 * The release-plan parser fails closed when the gates section is missing, so markdown
 * that merely lacks open items does NOT represent a closed release plan. Tests that want
 * "all documented gates closed" must supply the section with every row closed.
 */

/** Release checklist with no open, in-progress, or externally-blocked items. */
export const CLOSED_RELEASE_CHECKLIST_MARKDOWN = '- [x] release checklist closed\n';

/** Release plan whose gates section exists and whose every gate row is closed. */
export const CLOSED_RELEASE_PLAN_MARKDOWN = `- [x] release plan closed

## Production release gates (all releases)

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Product and API contract accuracy | Product | Published docs | **Closed** |
`;

/** Options pair for aggregateProductionReadinessGapAudit with all doc gates closed. */
export const CLOSED_RELEASE_DOC_OPTIONS = Object.freeze({
  releaseChecklistMarkdown: CLOSED_RELEASE_CHECKLIST_MARKDOWN,
  releasePlanMarkdown: CLOSED_RELEASE_PLAN_MARKDOWN,
});
