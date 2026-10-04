# Current-release implementation and verification

All 28 retained customer/public page implementations and the embedded target-check journey are complete locally and technically verified on 2026-10-04. Human visual approval (G1) and representative usability research (G3) remain separate, unperformed gates. This is not production-release signoff.

The final work is in the attached recovery worktree at /Users/checkred_admin/.codex/worktrees/current-release-recovery/astranull. A reset of the original checkout at 12:32:27 was recovered from a saved harness snapshot into this isolated worktree. HEAD remains e34ccd2783df1edfa40d3d44bf232f368fe61ab5. Nothing is staged, committed, pushed or deployed. All 165 original feedback files compare byte-for-byte with the originals.

Frontend implementation used Claude Code Opus 5.5 High with Design & Taste, UI/UX Pro Max, Impeccable and interaction-design. Backend initially used Grok 4.7; the user's later instruction switched remaining work to OpenCode Go glm-5.3-flash High. Model/provider/variant selection was verified. The orchestrator handled contracts, coordination, review, recovery and independent verification without authoring application code.

## Completed behavior

- Explicit target declarations and ownership; reviewed bounded checks and in-place results/proof/remediation.
- Shared evidence inspector with exact tenant/reference validation, original versus later proof, truthful custody and redaction.
- Independent provider attribution, explicit unknown/stale/simulation states, retained version-compatible observations and provider changes.
- Approved origin relations carried into signed Host/SNI/port/path; missing saved bound scope fails closed during recovery.
- Explicit same-finding retest intent, immutable expected behavior and audited per-finding closure without sibling closure or proof-of-fix claims.
- Authoritative server counts, matching filters and pagination, including severity aliases and legacy lifecycle reads.
- Frozen scoped reports, exact audit and notification context, explicit export/retry/sensitive actions, public access/recovery flows.
- Pure-black brand and fonts preserved; docked content reflows by available width, with responsive/keyboard/focus/error/empty states.
- Passive inspection never executes probes. Existing ownership, SOC, kill-switch and authorization safeguards remain.

## Verification

| Final independent check | Result | Evidence |
|---|---:|---|
| Unit and Node E2E | 4,318 passed, 0 failures, 0 skips | [Full test log](verification-evidence/final-independent-npm-test.log) |
| Serial integration including app-role Postgres RLS | 433 passed, 0 failures, 0 skips | Same full test log |
| Strict API shapes | 9 passed | [Contracts](verification-evidence/final-independent-contract.log) |
| Enabled dev/Postgres scale | 14 passed, 0 skips | [Scale](verification-evidence/final-independent-scale.log) |
| Final changed browser flows: dock, paging, accessibility, enabled estate scale | 39 passed, 0 skips | [Browser](verification-evidence/root-final-browser-checks.log) |
| Final affected frontend units | 115 passed | [Units](verification-evidence/root-final-affected-units.log) |
| Typecheck, lint, portal lint, safety, build, whitespace | Passed | [Build](verification-evidence/final-rebuild-after-dock.log), [Safety](verification-evidence/final-static-build-after-review.log) |

The complete browser set was run by Claude before the final dock/count changes: 351 passed, 0 failed, 1 gated scale skip. That gated case was then enabled and passed in the final independent 39 above. The entire 352 set was not repeated after the final focused changes. [Full browser log](verification-evidence/full-browser-before-final-dock.log).

Scale checks used 10,000 target groups, 100,000 findings and 5,000 declared targets. Tests used isolated stores and ephemeral Postgres databases with application-role RLS. Synthetic/injected probe data does not establish live provider or production validation.

## Review evidence and boundaries

Independent review closed defects in reference validation, custody trust, credential redaction, safe navigation, unbacked verdict presentation, exact counters, paging/accessibility, signed binding scope, immutable expected behavior and dock readability. [Review ledger](review-ledger.md) records findings and disposition.

[Dock before](visual-evidence/dock-before-1440-dark.png) and [dock after](visual-evidence/dock-after-1440-dark.png) show the readability fix. [Phone dashboard](visual-evidence/dashboard-undocked-375-dark.png), [group counts](visual-evidence/target-groups-375-light.png) and [linked findings](visual-evidence/findings-linked-group-375-dark.png) are final local candidates.

Live production/provider exercises, a Postgres-mode browser matrix, screen-reader sessions, human visual approval and representative usability research were not performed. Deferred staff/admin/SOC and standalone execution pages were not added or polished.

See [page acceptance](page-acceptance-matrix.md), [execution ledger](execution-ledger.md) and [machine-readable results](verification-results.json).
