# Senior frontend/backend consultation — protection-profile handoff

2026-10-04. Two separate senior engineering consultations inspected repository source **read-only**. No application files were changed, no tests were run for these consultations, and no implementation is implied. This file reconciles the user brief with existing capabilities and proposed UI placement.

## Joint decision

Extend the existing declared-target detail projection and reuse the current UI primitives. Keep CDN/WAF/hosting attribution separate from efficacy and ownership. Use server-side tenant-scoped analytics for dashboard/inventory; build history from retained observations, not the current snapshot projected backward.

UX final placement: compact Protection overview after the target header; dimension table beneath it; lower Overview/Validate/Findings/Changes & history tasks. Technical Evidence is accessible from provider rows, dimensions and selected check, rather than requiring a competing top-level workflow. Preserve old links while making this information-architecture change.

## Verified support versus required extension

| Area | Existing source-backed capability | Required extension / constraint |
| --- | --- | --- |
| Target identity | Exact value/kind/group/tags/ownership/expected behavior. Inventory includes sanitized metadata; detail omits general metadata. | Typed declared owner, service purpose/roles, criticality and effective inheritance, consistently serialized. Do not equate finding owner or WAF owner hint with host owner. |
| Protection attribution | Separate edge_detection WAF/CDN/cloud, provider sets, layers, sources, confidence/conflict, observed_at, test_run_id, corpus version. | Explicit layer/provenance scope, first-class origin-hosting Unknown, safe family-specific artifact references and dates. |
| Provider inspector | Existing layer/CNAME/IP/conflict disclosures and provider logo components. | Provider badge/button activation, exact source run/artifact link, recorded-only signals and accessible family context. |
| Efficacy | Attempted, conclusive tested, blocked, passed/allowed, inconclusive and per-class outcomes. | Applicable plan/version and exclusions; allowed-through-control does not alone prove application arrival. Explain denominator and remaining/inconclusive checks. |
| Origin | Canonical network_firewall direct-origin reachability/application-bypass states. | Separately declared/verified origin relationship, explicit authorized Host/SNI/port/path context and evidence/freshness. |
| Coverage | Target detail policy-bound/compatible checks; readiness groups credited for recent evidence. | Target × applicable check-pair plan/version/denominator with not-run, stale, inconclusive, blocked and excluded states. |
| WAF analytics | Optional add-on asset/vendor/product/entity/criticality/geography rollups, risk roadmap, snapshots/trend/drift. | Declared-host/service-role denominator and reconciled list/rollup contract. Do not duplicate the add-on or call every rollup missing. |
| History | Target ownership/run history and WAF add-on snapshots/drift; current per-target edge upsert. | Immutable target-layer observation/comparison timeline; current projection must resist older late results. |
| Concentration | WAF vendor footprint/overlap context. | Role-specific CDN/DNS/proven hosting concentration for distinct declared hosts/services, with unknown/overlap evidence. |
| Remediation | Findings, grouped WAF action items, remediation records and evidence-backed delegated retests. | Explicit affected-target/action membership, profile links and per-target retest outcomes. An issue group is not automatically one fix. |

## Concrete evidence-integrity corrections required before reuse

### Frontend

- `components/targets/domain-protection.tsx` can fall back from CDN attribution to a WAF vendor. Require independent family evidence before displaying a provider.
- `pages/target-detail-view.tsx` includes unconditional matched-header explanation and labels resolved addresses Anycast. Only show a method/match/address property if recorded by the source.
- `lib/domain-checks.mjs` can infer absent evidence methods/consistency from other hints. New inspector must show **Source not recorded** / **Consistency not evaluated** instead of inventing agreement.
- Provider-detection confidence is separate from verdict confidence `external_only`. Do not merge them into one assurance percentage.
- Current efficacy pass/fail labels differ from backend allowed/blocked counts. Use one explicit vocabulary and denominator; do not call allowed requests “successful protection.”

### Backend

- `src/services/targetDetail.mjs` legacy `waf_posture.origin_bypass.state` defaults to `not_exposed`, and marker_rules defaults to zero. Neither is an observation. Prefer explicit canonical not_tested/unknown states and provenance in the new profile.
- Current target-edge storage retains one current row; late completion can overwrite a newer observation. Propose retained accepted history and monotonic current selection by real observation ordering.
- WAF trend fallback can use current state for dates lacking an as-of snapshot. New host analytics should be Unknown before first evidence, respect declaration/archive times, and never reconstruct past protection from today’s state.
- Readiness validation coverage credits groups with recent evidence (30-day policy in current derivation), not all applicable target/check pairs. Do not relabel it as check completion or automatically copy that freshness policy into every dimension.
- `checks_applied` is not a complete applicability denominator. Model eligible scenario/check pairs, missing setup, scope/version and exclusions explicitly.
- Safe provider evidence projection currently omits some stored attribution material such as ASN/cname-specific matches. Add an explicit redacted projection if used; do not guess from whatever the UI happens to have.

These are source review findings and requirements. No correction was implemented in this documentation task.

## Origin authorization boundary

A hostname's profile must not select a new destination via `direct_ip` or arbitrary metadata. `src/lib/probeJobs.mjs` signed-worker Host/SNI controls require a verified IP literal/IP-literal URL for that path; profile metadata cannot bypass destination scope. Declare and verify the origin as its own target and define an explicit protected-host/origin relationship and authorization binding before promising direct-origin assessment. Existing compatible origin observations may be displayed in their actual tested scope; do not imply full origin inventory or blanket application bypass.

## Proposed data contract responsibilities

**Backend owner:** additive target profile projection, typed declarations/inheritance, canonical provider-role/provenance references, dimensional derivation, application/check-plan coverage, origin relationship, as-of aggregates, retained history, remediation lineage. Proposed fields should include status/reason, scope/unit, observation/freshness, evidence/run refs and derivation/version. They are not existing API promises.

**Frontend owner:** one target workflow, accessible provider inspector, dimension table, protocol-aware live trace, compact inventory columns/filters, metric-to-list navigation, baseline/changes comparison and per-target retest display. Reuse `Tabs`, `DataTable`, `FormModal`, provider logos, progress/disclosure and current request/refresh helpers.

**Shared contract decision:** target detail currently uses target_group:read; dedicated WAF uses waf:read plus feature gating. Define which optional configuration/efficacy fields may enter profile/rollups/export under each permission. Fingerprint data from authorized core probes must not imply access to confidential integration configuration. Every source/ref/filter remains tenant scoped.

**Declaration rule:** purpose differs from target kind; one host can have multiple declared service roles. Typed service IDs/endpoint declarations are needed for true service/login-URL counts. Group criticality inheritance must be explicit and returned with its source; free-form tags are not silently authoritative classification.

**Rollup rule:** counts and drill-down use identical predicates, independent of page size. Return units, denominator, numerator, unknown/stale/excluded categories, as_of/window, filters and equivalent list query. Zero denominator yields no percentage. Bound segment count/date ranges/example lists; paginate history/targets with stable keys. Avoid per-row detail requests and full-estate download.

**Freshness rule:** evaluate every dimension independently. A fresh CDN result cannot refresh stale origin/DNS evidence. Show last successful observation plus latest failed attempt; a timeout is not fresh denial or confirmed provider loss.

**Redaction rule:** do not expose cookies/credentials/arbitrary persisted metadata/request bodies through badges, JSON, clipboard, trace, export or history. Optional rule counts/blocking modes/configuration timestamps require actual integration evidence; external behavior must be labeled as behavior.

## Source map

Frontend:

- `apps/web/react/src/pages/target-detail-view.tsx`
- `apps/web/react/src/components/targets/domain-protection.tsx`
- `apps/web/react/src/lib/domain-checks.mjs`
- `apps/web/react/src/lib/target-detail-api.ts`
- `apps/web/react/src/pages/dashboard-page.tsx`
- `apps/web/react/src/components/findings/findings-list.tsx`
- `apps/web/react/src/lib/findings-helpers.ts`
- `apps/web/react/src/pages/refined/finding-group-detail.tsx`
- `apps/web/react/src/pages/finding-detail-view.tsx`

Backend:

- `src/services/targetDetail.mjs`, `targetGroups.mjs`, `targetEdgeDetectionStore.mjs`
- `src/lib/edgeDetectionPresenter.mjs`, `edgeDetectionProjection.mjs`, `probeJobs.mjs`
- `src/services/wafCoverageService.mjs`, `readiness.mjs`, `wafOrchestrator.mjs`
- Related Postgres repositories/adapters and WAF drift/action-item services should be located by the implementing agent before contract changes.

## Meaningful joint acceptance checks

1. Cloudflare edge with unknown origin yields independent family fields and **Origin hosting unknown**; no guessed Anycast/header match/vendor agreement.
2. Provider click opens exact authorized evidence; missing confidence/source stays explicit.
3. One passed application check leaves untested DNS/network dimensions unknown; an open origin finding remains visible.
4. Allowed/blocked/inconclusive/not-run/stale counts reconcile against the applicable scoped plan.
5. Multi-role hosts, duplicate hostname/URL targets, zero applicability and unknown criticality are counted correctly.
6. Dashboard filters/counts match paginated inventory under permissions and add-on gates.
7. Old late events/replay cannot regress the current projection; history does not show protection before declaration/first evidence.
8. Drift requires comparable observations; transport failure/corpus/scenario changes are not silent regressions.
9. Provider concentration separates roles, overlaps and unknown dependencies; no inferred outage boundary.
10. Origin relationships, cursors, evidence refs, aggregates and exports reject cross-tenant scope.
11. Partial retest cannot resolve siblings; only appropriate finalized evidence advances remediation status.
12. Direct bounded-check evidence does not establish volumetric capacity; existing authorization remains enforced.
13. Logs remain bounded, selected checks/focus persist during refresh, and disconnect/stale data is visible.
14. Verify dark/light, 375/768/1024/1440px, 200% zoom, keyboard, focus restoration, text alternatives and reduced motion.
15. Require dev-json/Postgres contract parity and audited declaration/lifecycle changes in the future implementation task.

No new test implementation or application changes are requested by this file. Use [skills and handoff](05-skills-and-handoff.md), with backend data truth agreed before frontend labels promise unsupported results.

## Shared visual/task handoff

Use [reference specifications](11-reference-screen-specifications.md), [component standard](12-component-visual-specification.md), [responsive budgets](14-content-and-responsive-task-budgets.md) and [feedback/navigation](16-feedback-responsiveness-and-daily-use.md). Page focus: G0 contract readiness and G2 evidence integrity; prototype fixtures must not imply missing endpoints. See [acceptance gate](17-design-acceptance-and-handoff-gates.md). All references remain proposed until rendered and explicitly approved; user task results are Not run.
