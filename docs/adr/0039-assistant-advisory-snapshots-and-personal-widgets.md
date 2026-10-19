# ADR-0039: Advisory snapshots and personal widgets

- Date: 2026-10-19
- Status: Implemented locally; release and production enablement pending
- Extends: ADR-0037, ADR-0008, ADR-0019

## Decision

Five read-only assistant surfaces reuse the existing structured-job lifecycle: provider fix packs, combined-risk stories, validation-plan proposals, exact findings filters, and personal widgets. They do not add execution authority, provider credentials, discovery, environments, customer agents, scoring rules or finding groups.

Compute deterministic data before optional interpretation. Provider guidance comes from the published remediation catalog. Risk stories separate recorded metadata from conditional hypotheses; they do not establish causality. Validation candidates come from the complete target-specific catalog with declarations/origin prerequisites and existing customer/launcher eligibility rules. The service temporarily imports the pure `check-picker.mjs` selection helpers to avoid a second divergent eligibility implementation; backend admission remains authoritative. Only an explicit review/confirmation through the existing scan launcher can execute a selection.

Natural-language filtering compiles to the existing exact AND predicates (`q`, `status`, `severity`, `check_id`, `target_id`, `test_run_id`). Literal search is accepted only from an explicit quoted search. Unsupported providers, dates, OR, negation, SQL, ambiguous entities and multiple values are refused rather than approximated. The initial vocabulary is at most 100 permitted entities of each kind; absent entities are not selectable. Apply replaces the actual server-query state, resets pagination and shares only the validated filter object, never the question.

## Private evidence binding

`createStructuredJob` captures a JSON-cloned validation snapshot of at most 64 KiB separately from scalar audited context. Parsers receive `{sources, context, validation}`. Snapshots are never returned by public jobs, runner leases or audits and are discarded on completion, cancellation or lease timeout. They are not durable result storage.

The job separately retains private required read permissions and bounded source identity bindings (at most 200 per kind, 400 combined). Reads require the original tenant and user plus current role/token scopes. HTTP retrieval of a result re-resolves required findings/targets/runs and refuses missing, archived, foreign or unavailable sources. Model-produced filter entity references are rechecked when they become known. This is current access validation, not a guarantee that evidence content has not changed since the explicitly dated snapshot. Jobs/results remain process-local with the existing one-hour TTL and are lost on restart.

All five purposes are tool-less, bounded, optional and subject to shared tenant/per-user limits. A malformed model answer fails closed to deterministic data or an unapplied filter preview. No job can invoke run/schedule/provider mutations. Cancellation stops acceptance/polling; it does not prove an already running external model process was interrupted.

## Durable definitions, not generated dashboards

Migration `0085_assistant_widgets.sql` stores only personal widget definitions: bounded name/question, `summary` or `finding_list`, optional declared target and exact severity, version and timestamps. It stores neither model output nor arbitrary code/queries/markup/chart schemas. Twelve unique slots enforce the per-user quota, including concurrent writers. FORCE RLS binds both `app.tenant_id` and `app.user_id`; repository queries also specify both identities. Same-tenant user/target foreign keys prevent cross-tenant ownership. Update/delete require an expected version; conflicts do not overwrite newer work.

Development persistence stages definition and chained audit together before durable file replacement. PostgreSQL mutations and audits share a tenant transaction. PostgreSQL mode fails closed if its repository is unavailable, never falling back to the development store. Widget access is personal, not a team-sharing feature. Inaccessible target-scoped definitions return ID/version-only removal handles; their configuration and source data remain hidden. Explicit deletion relies on repository-enforced tenant/user ownership and version CAS, not current source visibility, so inaccessible definitions cannot permanently consume the twelve slots. Edit/refresh still require current scope access; there is no automatic cleanup.

Data refresh queries at most 200 matching findings and shows at most six rows. Counts are certified totals only for complete finding results; incomplete samples remain explicitly labelled. Explicit target scope is validated against the bounded permitted target inventory, so an absent target fails closed. An arbitrary question never changes the defined data predicates or creates a metric. Reload recomputes data without a model request. Only explicit Ask AI requests commentary, with citations bound to the computed snapshot. Preview precedes save; edit, conflict recovery, remove confirmation and explicit cancellation/retry remain separate actions.

## Migration rollout and rollback

Migration 0085 is additive: it creates the personal-definition table, its constraints and its FORCE RLS policy without modifying existing tables or writers. Apply it through the normal versioned migration runner and transactional application-role grants after the deployment's verified encrypted backup and before activating the new control plane. Record the actual migration head and role/RLS checks; a skipped local harness or an old deployment is not apply evidence for this release.

Code rollback retains the table and saved definitions. The previous application does not read or write it, and a subsequent forward deployment must reuse it rather than drop and recreate it. Do not reverse this migration or discard definitions to recover a code release. If a constraint or policy needs repair, use a reviewed forward migration with ownership and isolation regression tests. Database restore is a separate destructive, outage-causing operation requiring explicit incident/change approval under the AWS runbook; ordinary code rollback does not authorize it.

The owned local PostgreSQL compatibility test explicitly provisions populated 0084, then applies only 0085 and reprovisions application privileges. It uses the unchanged pre-feature catalog and audit code under the real non-owner/NOBYPASSRLS application login to verify preserved legacy records, constraints and RLS, previous-head startup acceptance, and successful legacy reads/writes. It saves a widget, simulates old-code operation without removing the table, reconstructs the widget repository and verifies the exact definition/version survives an all-skipped migration rerun. This is local contract compatibility evidence, not an actual previous-image rollback or production migration/backup proof.

## Release boundary

The user has requested a code release through the documented CI-to-AWS process. That authorization does not enable production AI, change runner policy, migrate model providers or authorize live target probes. Production AI must be confirmed disabled before promotion; source defaults are not proof of the host's effective configuration. Preserve existing upstream runner policy without incorporating the previously denied runner work into this feature delta. A separate explicitly authorized runner review, provider privacy/retention and regional processing review, migration rollout and production acceptance are prerequisites to AI enablement. Local fake-runner/browser and application-role PostgreSQL tests do not substitute for these approvals. Record actual commit, CI, deployment and independent verification outcomes separately in `PROGRESS.md`.
