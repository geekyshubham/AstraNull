# AstraNull Feature and Functionality Coverage Matrix (React-current)

Updated: 2026-07-05

This matrix reconciles the codebase feature inventory with **where each capability appears in the React portal today**. It supersedes audits that referenced deleted legacy surfaces (`apps/web/app.js`, `landing.html`, `internal-admin.js`).

## Audit basis (current)

| Source | Role |
|--------|------|
| `apps/web/react/src/pages/*` | Customer/staff UI implementation |
| `apps/web/react/src/lib/api.ts` | Portal data loading |
| `apps/web/react/src/lib/navigation.ts` | Route inventory |
| `apps/web/react/src/lib/prototype-manifest.ts` | Open Design prototype parity catalog |
| `src/lib/http.mjs` | Static route aliases |
| `src/contracts/roles.mjs`, `src/contracts/staffRoles.mjs` | RBAC |
| `docs/api.md` | API inventory |
| `docs/ux/01-pages-and-tabs.md` | UX tab depth spec |
| Feature contracts under `src/contracts/*` | Backend capability inventory |
| `scripts/react-portal-browser-e2e.mjs` | Browser verification |

## Status legend

| Status | Meaning |
|--------|---------|
| **Visible** | Meaningful React UI; data from real APIs |
| **Partial** | UI exists; not every UX-spec tab/action/state exposed |
| **API-only** | Backend exists; no customer portal control (may be intentional) |
| **Operator-only** | Scripts/workers/K8s cron — not product UI |
| **Staff-only** | Staff React surface (`#admin`, `#internal-soc`) |
| **By design hidden** | SOC execution, probe workers, unmanaged traffic |

## Stale gaps from pre-React audit — corrected

| Old claim | React-current status |
|-----------|---------------------|
| `internal-admin.js` 404; staff console broken | **Fixed** — `StaffSurfacePage` at `/internal/admin#admin` uses `/internal/admin/*` APIs |
| `landing.html` / per-page HTML shells | **Merged** — single SPA: `apps/web/index.html` + `react-app.js` |
| Integrations page missing | **Visible** — `#integrations` (`IntegrationPage`) |
| Sign-up status lookup missing | **Visible** — `/signup-status` (`SignupStatusPage`) |
| Custody verify API-only | **Visible** — Reports, Evidence, Report detail (`/v1/custody/verify`) |
| Agent revoke API-only | **Visible** — Agents fleet + `#agent-detail` Actions |
| Run cancel/finalize not surfaced | **Visible** — `#runs` + ValidationSurfacePage |
| Subscription/support pages missing | **Visible** — `#subscription`, `#support` |

## Route inventory (React)

### Public (6 routes)

| Route | Component | Status |
|-------|-----------|--------|
| `/` | `PublicLandingPage` | Visible |
| `/login` | `LoginPage` | Visible (dev-headers + OIDC/bundled-staging) |
| `/signup` | `SignupPage` | Visible |
| `/signup-status` | `SignupStatusPage` | Visible |
| `/internal/admin/login` | `StaffLoginPage` | Visible |
| `/app` | React shell | Visible |

### Customer portal hash routes (38+)

All routes in `router.tsx` + `navigation.ts` are **Visible or Partial** — none Static/pending. See `docs/feature-ui-coverage-matrix.md` for per-route slice status.

### Staff (`/internal/admin`)

| Route | Status | Notes |
|-------|--------|-------|
| `#admin` | Visible | Signup approve, tenants, entitlements, approvals |
| `#tenant-detail` | Visible | Staff tenant administration |
| `#internal-soc` | Staff-only | SOC impersonation surface |

## Prototype parity (Open Design)

Prototype project: `c2cc0262-cba8-47ed-a941-3b02fcaf8159`

| Check | Status |
|-------|--------|
| All prototype HTML pages have React route equivalent | **Yes** — see `PROTOTYPE_SURFACES` in `prototype-manifest.ts` |
| Design tokens (Geist, shell.css contract) | **Ported** — `apps/web/react/src/styles.css` |
| Full tab depth per prototype HTML | **Partial** — many pages implement core flows, not every sub-tab |
| Pixel-perfect match to static HTML | **Not claimed** — functional + design-system parity |

## Feature summary (honest counts)

| Bucket | Approx. | Examples |
|--------|---------|----------|
| **Visible in React** | Core product flows | Onboarding, agents, runs, findings, WAF posture lists, high-scale intake, SOC console, staff admin |
| **Partial UI** | UX-spec tab depth | Dashboard tabs, target-group tabs, agents logs/upgrades, WAF orchestrator scheduler |
| **API-only (customer)** | Advanced lifecycle | Agent update rollout UI, trust keys, full WAF validation finalize/orchestrator, CVE feed ingest UI |
| **Operator-only** | Platform | 105 npm scripts, probe worker, K8s cronjobs, migrations, release evidence submit CLI |
| **By design hidden** | Safety | `/internal/soc/*` execution from customer bundle, raw probe jobs, unmanaged traffic |

**Not every row in the historical 200+ feature inventory is meant to be a portal button.** Operator-only and API-only items are production backend capabilities, not UI gaps.

## Known remaining Partial items (Phase C work queue)

| Area | Gap | Owner phase |
|------|-----|-------------|
| ~~Dashboard~~ | ~~Full tab set: Business Services, Risk Trends, Evidence Feed~~ | **Done (PP-03 2026-07-05)** — Overview + Business Services + Risk Trends + Evidence Feed tabs backed by `/v1/state`, target-groups, agents, runs, findings, evidence, audit |
| Target groups | Expected behavior, agents, checks, findings tabs on detail | OD-06, PP-06 |
| Agents | UX-spec depth beyond API-backed tabs (host log tail, CPU/memory telemetry) | FM-AGENT (documented boundary) |
| ~~Checks~~ | ~~Full family tabs (Recommended, L3/L4, DNS, …)~~ | **Done (FM-VALIDATION 2026-07-05)** — `#checks` All/Safe/SOC scope + Recommended/Origin/L3/L4/DNS/L7/Protocols/High-Scale/Custom tabs from `/v1/checks` |
| ~~Runs~~ | ~~Raw events, correlation sub-tabs~~ | **Done (FM-VALIDATION 2026-07-05)** — `#runs` and `#run-detail` expose Summary/Timeline/Probe/Agent/Correlation/Evidence/Raw Events tabs from `/v1/test-runs/:id` + `/events` |
| ~~Findings~~ | ~~By vector, SLA dashboard tabs~~ | **Done (FM-VALIDATION 2026-07-05)** — `#findings` Open/By Target Group/By Vector/Accepted Risk/Closed/SLA tabs; assignee + notes triage via `PATCH /v1/findings/:id` |
| ~~WAF posture~~ | ~~Roadmap tab, validation plan scheduler, drift scan controls, exceptions UI~~ | **Done (FM-WAF 2026-07-05)** — Overview/Roadmap/Assets tabs; drift queue + scan + retest; validation-plan operator panel; exceptions list/create |
| Agent updates | Signed release **creation** UI (manifest/distribution ceremony) | FM-AGENT (operator CLI boundary) |
| Settings users tab | No customer tenant-user invite/disable API | FM-CORE (boundary) |
| Enterprise SSO | Per-customer IdP claim mapping | External ops |
| PDF reports | Backend has json/md/html only | Intentional boundary |

## Production readiness tiers

| Tier | Definition | Current |
|------|------------|---------|
| **T1 UI-plugged** | Routed pages use real APIs; E2E green | **Met** |
| **T2 UX-complete** | All `docs/ux/01-pages-and-tabs.md` tabs implemented | **Not met** |
| **T3 Feature-complete** | Every API in `docs/api.md` has UI or documented boundary | **Not met** |
| **T4 Production launch** | `docs/release-checklist.md` + per-customer IdP/KMS/agents | **External ops** |

`/complete-portal` targets **T1** fully and drives **T2/T3** via Phase C–F until documented boundaries.

## FM-CORE — Auth, RBAC, signup, tenants

Phase C classification (2026-07-05). Surfaces: `public-pages.tsx`, `App.tsx`, `app-shell.tsx`, `route-access.ts`, `page-components.tsx` (Settings, StaffSurface), `governance-pages.tsx`, `api.ts`. Contracts: `src/contracts/roles.mjs`, `src/contracts/staffRoles.mjs`.

| Feature | Classification | React surface | API / notes |
|---------|----------------|---------------|-------------|
| Public landing | **Visible** | `/` `PublicLandingPage` | `GET /v1/public/site-config`; signup CTA gated by `signup_enabled` |
| Customer login | **Visible** | `/login` `LoginPage` | `dev-headers`, `POST /v1/auth/bundled-staging-login`, OIDC redirect when `auth_mode=oidc-jwt` |
| Staff login | **Visible** | `/internal/admin/login` `StaffLoginPage` | Staff principal + `staff_role`; separate surface from customer bundle |
| Signup intake | **Visible** | `/signup` `SignupPage` | `POST /v1/signup-requests`; approval-gated, no auto-provision |
| Signup status | **Visible** | `/signup-status` `SignupStatusPage` | `GET /v1/signup-requests/:id` |
| Session gate | **Visible** | `App.tsx` `ensurePortalSession` | Redirects unauthenticated users; dev-headers + OIDC + bundled staging |
| Role-based sidebar nav | **Visible** | `app-shell.tsx` | `NAV_ITEMS.filter(canAccessRoute)` aligned to `roles.mjs` PERMISSIONS |
| Hash route guard | **Visible** | `App.tsx` | Forbidden `#hash` routes redirect to `#dashboard` (prevents nav bypass) |
| Notifications nav | **Visible** | Sidebar; Settings/Support deep links | Gated by `notification:read` — **hidden for `viewer`** |
| Audit nav | **Visible** | Sidebar; Settings audit tab + links | Gated by `audit:read` — **visible for `auditor`**; hidden for `viewer`/`engineer` |
| Release evidence nav | **Visible** | Sidebar; Settings/Support deep links | Gated by `release_evidence:read` — **visible for `auditor`** |
| SOC console nav | **Visible** | Sidebar `#soc` | Gated by `soc:high_scale`; staff execution uses `#internal-soc` |
| Tenant profile | **Visible** | `#settings` Organization | `GET/PATCH /v1/tenants/current` (name, `privacy_settings`) |
| Retention policy | **Visible** | `#settings` Data retention | `PATCH /v1/tenants/current` metadata + evidence retention |
| Bootstrap tokens | **Visible** | `#settings` API keys | `POST /v1/bootstrap-tokens`, `POST …/:id/revoke` |
| Service accounts | **Visible** | `#settings` API keys | `POST/POST rotate/POST revoke /v1/service-accounts` |
| Secret vault | **Partial** | `#settings` Secret vault | Create/rotate for owner/admin; list redacted |
| Users & roles directory | **Partial** | `#settings` Users & roles | Read-only session + IdP posture; **boundary:** no customer tenant-user API |
| Enterprise SSO config | **API-only** | `#settings` SSO tab | Posture readout only; per-customer IdP/MFA is **external ops** |
| Staff signup queue | **Staff-only** | `#admin` `StaffSurfacePage` | `GET /internal/admin/signup-requests`, approve/reject |
| Staff tenant lifecycle | **Staff-only** | `#admin`, `#tenant-detail` | `/internal/admin/tenants/*` activate/suspend, support owner |
| Staff entitlements | **Staff-only** | `#admin` | `POST /internal/admin/tenants/:id/entitlements` |
| Staff internal audit | **Staff-only** | `#admin` | `GET /internal/admin/audit-log` (`staff:audit:read`) |

**FM-CORE verdict:** **PASS (T1)** — auth, signup, tenant settings, and RBAC-aligned navigation are wired to real APIs. Nav and deep links respect `roles.mjs` (`viewer` lacks Notifications; `auditor` sees Audit + Release evidence). **Remaining partials:** customer user-directory management (staff-operated), enterprise IdP per-tenant mapping (external ops).

## FM-AGENT — Registration, heartbeat, revoke, updates

Phase C classification (2026-07-05). Surfaces: `AgentsPage`, `OnboardingPage`, `AgentDetailView` (`detail-pages.tsx`). Backend: `src/services/agents.mjs`, `src/services/agentUpdates.mjs`, `src/services/placement.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Bootstrap token create | **Visible** | `#agents` Install tab, `#onboarding`, `#settings` | `POST /v1/bootstrap-tokens` |
| Agent registration | **API-only** | Install commands only; registration is host agent | `POST /v1/agents/register` (bootstrap secret) |
| Fleet list | **Visible** | `#agents` Fleet tab; metrics on dashboard | `GET /v1/agents` |
| Heartbeat verification | **Visible** | `#onboarding` polls `GET /v1/agents` every 3s | Agent-side `POST /v1/agents/:id/heartbeat` |
| Revoke | **Visible** | Fleet + `#agent-detail` Actions | `POST /v1/agents/:id/revoke` |
| Placement diagnostics | **Visible** | `#agents` Placement tab | `GET /v1/placement/reviews`, readiness `agent_placement` factor |
| Health tab (heartbeat freshness) | **Visible** | `#agents` Health tab, `#agent-detail` | Derived from `GET /v1/agents` timestamps + status |
| Capabilities tab | **Visible** | `#agents` Capabilities tab, `#agent-detail` | `capabilities[]` on agent record |
| Logs tab | **Partial** | Audit-trail slice only | `GET /v1/audit-log` filtered for `agent.*` / `agent_update.*`; **boundary:** no host operational log API |
| Upgrades — list + rollback | **Visible** | `#agents` Upgrades tab | `GET /v1/agent-updates`, `POST /v1/agent-updates/:id/rollback` |
| Upgrades — release create | **Operator-only** | Documented boundary on Upgrades tab | `POST /v1/agent-updates` requires signed manifest + HTTPS distribution URLs; use `npm run agent:package` / evidence scripts |
| Trust keys — list/add/revoke | **Visible** | `#agents` Upgrades tab | `GET/POST /v1/agent-update-trust-keys`, `POST …/:id/revoke` |
| Agent update poll/status | **API-only** | Agent host polls; not customer UI | `GET /v1/agents/:id/update`, `POST …/update-status` (Bearer agent credential) |
| Agent jobs / observations | **By design hidden** | SOC/validation loop only | `GET/POST /v1/agents/:id/jobs*`, `POST …/observations` |
| mTLS gateway identity | **Operator-only** | Fingerprint shown when registered | `ASTRANULL_AGENT_IDENTITY_MODE=gateway-mtls`; evidence via `agent:mtls:evidence` |
| Packaged install matrix | **Operator-only** | Copy-paste install snippets only | `agents/linux/*`, Helm charts, `npm run agent:install:matrix:evidence` |

**FM-AGENT verdict:** **PASS (T1)** — fleet, onboarding heartbeat, revoke, placement, capabilities, audit-trail logs, release list/rollback, and trust-key management use real APIs with no mock operational rows. **Remaining gaps (T2/T3, documented):** host operational logs, CPU/memory/disk telemetry, release creation ceremony UI, unattended daemon rollout drills (external ops).

## FM-VALIDATION — Checks, runs, findings, evidence

Phase C classification (2026-07-05). Surfaces: `ValidationSurfacePage` (`functional-surfaces.tsx`), `RunDetailView` / `FindingExplanationPanel` (`detail-pages.tsx`, `finding-explanation-panel.tsx`), `PolicyPage` (`page-components.tsx`), `run-proof-panels.tsx`. Backend: `src/contracts/checks.mjs`, `src/services/testRuns.mjs`, `src/services/findings.mjs`, `src/services/evidence.mjs`, `src/services/correlation.mjs`, `src/services/safeTestPolicy.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Check catalog browse | **Visible** | `#checks` | `GET /v1/checks`; All/Safe/SOC scope tabs + family tabs (Recommended, Origin, L3/L4, DNS, L7/API, Protocols, High-Scale) |
| Custom check binding | **Partial** | `#checks` Custom tab | Empty-state links to `#test-policies`; **boundary:** no standalone custom-check create API — policies bind safe catalog checks |
| Test policy create/patch/archive | **Visible** | `#test-policies` | `POST/PATCH/DELETE /v1/test-policies`; cadence, expected verdict, safe windows |
| Safe run start | **Visible** | `#runs`, `#onboarding` | `POST /v1/test-runs` with declared target group + target + safe check |
| Run list + detail | **Visible** | `#runs`, `#run-detail` | `GET /v1/test-runs`, `GET /v1/test-runs/:id` |
| Run cancel / finalize | **Visible** | `#runs`, `#run-detail` Actions | `POST /v1/test-runs/:id/cancel`, `POST …/finalize` |
| Run timeline + raw events | **Visible** | `#runs`, `#run-detail` Timeline + Raw Events tabs | `GET /v1/test-runs/:id/events` |
| Probe results panel | **Visible** | `#runs`, `#run-detail` Probe Results tab | Filtered `probe_result` events from run events API |
| Agent observations panel | **Visible** | `#runs`, `#run-detail` Agent Observations tab | Filtered `agent_observation` / `agent_no_observation` events |
| Correlation + verdict explanation | **Visible** | `#runs`, `#run-detail` Correlation tab; findings explanation | `correlation.mjs` verdict on run detail; `VerdictExplanationPanel`, `TruthTablePanel` |
| Traffic path diagram | **Visible** | Run summary tabs | Derived from verdict state in `run-proof-panels.tsx` |
| Findings list + KPIs | **Visible** | `#findings` | `GET /v1/findings`; open/accepted/closed-30d/SLA breach metrics |
| Findings triage tabs | **Visible** | `#findings` | Open, By Target Group, By Vector, Accepted Risk, Closed, SLA |
| Finding assignee + notes | **Visible** | `#findings` triage form | `PATCH /v1/findings/:id` (`assignee`, `notes`) |
| Finding status workflow | **Visible** | `#findings` row actions | Accept risk, close via `PATCH` `status` |
| Finding export with custody | **Visible** | `#findings` export | `POST /v1/findings/:id/export` |
| Finding retest | **Visible** | `#findings` retest | Safe run (`POST /v1/test-runs`), WAF validation (`POST /v1/waf/validations`), or CVE retest when finding metadata provides context |
| Finding explanation | **Visible** | `#findings` detail panel | Loads linked run + events for verdict explanation |
| Evidence vault list | **Visible** | `#evidence` | `GET /v1/evidence` |
| Evidence detail | **Visible** | `#evidence`, run Evidence tab | `GET /v1/evidence/:id` |
| Evidence chain export | **Visible** | `#evidence` | Client-side chain from vault + runs + verdicts; `POST /v1/custody/verify` on export digest |
| Event ingest | **API-only** | — | `POST /v1/events` — probe/agent pipeline; not customer portal |
| Probe job dispatch | **By design hidden** | — | Signed-worker jobs via `/internal/probe/*`; SOC/validation loop only |
| Agent observation submit | **By design hidden** | — | `POST /v1/agents/:id/observations` — agent host only |
| Correlation engine (internal) | **Operator-only** | Verdict UI only | `correlation.mjs` + `testRuns.mjs`; no direct customer API |
| Evidence snapshot signing | **Operator-only** | Release evidence boundary | KMS/signing ceremony; digest verify exposed, not signing UI |
| Scheduled policy execution | **Operator-only** | Policy records visible | Cadence stored; external scheduler/worker runs policies |

**FM-VALIDATION verdict:** **PASS (T1)** — checks catalog, test policies, safe runs (start/cancel/finalize), full run tab depth (timeline, probe, agent, correlation, evidence, raw events), findings triage (tabs, assignee, notes, export, retest), and evidence vault + chain export with custody verify are wired to real APIs. **Remaining gaps (T2/T3, documented):** custom-check authoring beyond policy binding, per-evidence immutable snapshot signing UI (operator/KMS boundary), automated policy scheduler UI (operator worker boundary).

## FM-WAF — Posture, CVE, drift, orchestrator

Phase C classification (2026-07-05). Surfaces: `PostureSurfacePage`, `DetailRoutePage` (`waf-asset-detail`, `cve-detail`), `ValidationSurfacePage` (finding WAF retest). Backend: `wafPosture.mjs`, `wafOrchestrator.mjs`, `wafDriftWorker.mjs`, `cvePipeline.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| WAF feature gate | **Visible** | `#waf-posture` disabled state | `ASTRANULL_WAF_POSTURE_ENABLED=1`; `/v1/waf/*` → `404 waf_feature_disabled` when off |
| Asset declare/create | **Visible** | `#waf-posture` create form, Assets tab | `POST /v1/waf/assets` |
| Asset detail + effectiveness | **Visible** | `#waf-asset-detail` | `GET /v1/waf/assets/:id` |
| Coverage summary | **Visible** | `#waf-posture` Overview | `GET /v1/waf/coverage` |
| Risk roadmap (Tier 1–4) | **Visible** | `#waf-posture` Roadmap tab | `GET /v1/waf/coverage/risk-roadmap` |
| Safe validation start | **Visible** | `#waf-asset-detail` Actions, findings retest | `POST /v1/waf/validations` |
| Validation finalize | **Visible** | Findings retest path (orchestrator closure) | `POST /v1/waf/validations/:id/finalize` |
| Drift events list + triage | **Visible** | `#waf-posture` drift queue | `GET /v1/waf/drift-events`, `PATCH /v1/waf/drift-events/:id` |
| Drift scan run + latest | **Visible** | `#waf-posture` drift scan panel | `POST /v1/waf/drift-scans/run`, `GET /v1/waf/drift-scans/latest` |
| Drift retest workflow | **Visible** | `#waf-posture` retest controls | `POST /v1/waf/drift-events/:id/retest`, `POST /v1/waf/retests/:id/execute`, `POST /v1/waf/retests/:id/complete` |
| Validation plans (operator) | **Visible** | `#waf-posture` validation-plan panel | `GET/POST /v1/waf/validation-plans`, `POST …/:id/execute`, `POST …/:id/cancel` |
| WAF exceptions | **Visible** | `#waf-posture` exceptions panel, `#waf-asset-detail` | `GET /v1/waf/exceptions`, `POST /v1/waf/assets/:id/exception` |
| CVE pipeline CRUD + triage | **Visible** | `#cve-pipeline`, `#cve-detail` | `POST/GET /v1/waf/cve-pipeline`, `POST …/:id/triage`, `validate`, `match`, `playbook` |
| CVE coordinated retest | **Visible** | Findings retest + `#cve-pipeline` | `POST /v1/waf/cve-pipeline/:id/retest` / `coordinated-retest` |
| Remediation action items | **Visible** | `#remediation` | `GET/POST/PATCH /v1/waf/action-items`, `POST …/:id/deliver` (dry-run) |
| Coverage analytics (vendors/entities/geo) | **API-only** | — | `GET /v1/waf/coverage/vendors` etc.; T2 UX depth not routed |
| WAF report exports | **API-only** | — | `GET /v1/waf/reports/:kind/export`; operator/staging boundary |
| Connector poll on posture page | **Partial** | `#integrations` full surface | Connector CRUD on Integrations; posture connector health panel deferred |
| Baseline approve | **API-only** | — | `POST /v1/waf/baselines/:id/approve`; ceremony boundary |
| Orchestrator production runner | **Operator-only** | Documented on validation-plan panel | `npm run waf:orchestrator:runner` external scheduler |
| CVE feed ingest | **Operator-only** | — | `POST /v1/waf/cve-pipeline/ingest`; operator CLI |

**FM-WAF verdict:** **PASS (T1)** — assets, coverage, roadmap, drift queue (patch/retest/scan), validation-plan operator controls, exceptions, CVE pipeline, and remediation action items use real APIs. **Remaining gaps (T2/T3, documented):** extended coverage analytics tabs, WAF report export panel, connector health on posture page, baseline approval ceremony, production orchestrator scheduling evidence (external ops).

## FM-DISCOVERY — Entities, candidates, import

Phase C classification (2026-07-05). Surfaces: `PostureSurfacePage` (`discovery` route), `DetailRoutePage` (`discovery-entity`). Backend: `externalDiscovery.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Discovery feature gate | **Visible** | `#discovery` disabled state | `ASTRANULL_EXTERNAL_DISCOVERY_ENABLED=1` |
| Entity declare | **Visible** | `#discovery` create form | `POST /v1/discovery/entities` |
| Candidate inbox list | **Visible** | `#discovery` table + metrics | `GET /v1/discovery/candidates`, `GET /v1/discovery/inbox` |
| Candidate approve/reject | **Visible** | `#discovery` row actions | `POST /v1/discovery/candidates/:id/approve`, `…/reject` |
| Import to target group | **Visible** | `#discovery` import action | `POST /v1/discovery/candidates/:id/import` (+ optional WAF asset) |
| Entity detail | **Visible** | `#discovery-entity` | List-backed entity metadata + decision trail |
| Discovery summary report | **Visible** | Metrics from portal loader | `GET /v1/discovery/reports/summary` |
| Passive source ingest | **Operator-only** | — | `POST /v1/discovery/sources/ingest`; no live discovery sources in dev |
| Candidate create (operator) | **Operator-only** | — | `POST /v1/discovery/candidates`; approval-gated intake |

**FM-DISCOVERY verdict:** **PASS (T1)** — entity declare, candidate approve/reject/import, inbox metrics, and entity detail are wired to real APIs with feature-flag fail-closed behavior. **Remaining gaps (T2/T3, documented):** live passive discovery source connectors (external ops), dedicated discovery inbox sub-tab depth per UX spec.

## FM-SUPPLY — Risks, phases

Phase C classification (2026-07-05). Surfaces: `PostureSurfacePage` (`supply-chain` route), `DetailRoutePage` (`supply-chain-detail`). Backend: `supplyChainRisk.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Risk create/list | **Visible** | `#supply-chain` | `GET/POST /v1/waf/supply-chain/risks` |
| Risk detail | **Visible** | `#supply-chain-detail` | `GET /v1/waf/supply-chain/risks/:id` |
| Risk state confirm | **Visible** | `#supply-chain-detail` Actions | `PATCH /v1/waf/supply-chain/risks/:id/state` |
| Phase authorization (AP2/AP3) | **Visible** | `#supply-chain-detail` authorize form | `POST /v1/waf/supply-chain/risks/:id/phase-authorization` (`supply_chain:authorize`) |
| Phase authorization readback | **Visible** | Detail overview (`phase_authorizations[]`) | `GET …/phase-authorization` |
| Remediation ticket create | **API-only** | — | `POST /v1/waf/supply-chain/risks/:id/remediation-ticket`; connector delivery boundary |
| Assess dangling CNAME/dependency | **Operator-only** | — | `POST /v1/waf/supply-chain/assess/*`; operator ingest |
| Source ingest | **Operator-only** | — | `POST /v1/waf/supply-chain/sources/ingest` |

**FM-SUPPLY verdict:** **PASS (T1)** — supply-chain risk create/list/detail, state confirm, and customer phase authorization (AP2/AP3) use real APIs. **Remaining gaps (T2/T3, documented):** remediation ticket connector delivery UI, automated assess/ingest operator workflows.

## FM-HIGHSCALE — Requests, artifacts, SOC

Phase C classification (2026-07-05). Surfaces: `HighScalePage` (customer), `SocConsolePage` (customer `#soc` + staff `#internal-soc`). Backend: `highScale.mjs`, `authorizationTemplates.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Governed request create | **Visible** | `#high-scale` intake form | `POST /v1/high-scale-requests` |
| Request list + pack status | **Visible** | `#high-scale` tables/metrics | `GET /v1/high-scale-requests` |
| Authorization artifact upload | **Visible** | `#high-scale` metadata upload grid | `POST /v1/high-scale-requests/:id/artifacts` |
| Lifecycle timeline (read-only) | **Visible** | `#high-scale` audit_trail panel | Derived from request `audit_trail` |
| Provider checklist (read-only) | **Visible** | `#high-scale` | From request payload |
| SOC approve/schedule/start/stop/close | **Staff-only** | `#soc`, `#internal-soc` | `/internal/soc/high-scale/:id/*` — **not** in customer bundle |
| SOC artifact review | **Staff-only** | `#soc`, `#internal-soc` | `POST …/artifacts/:id/review` |
| Kill switch | **Staff-only** | `#soc`, `#internal-soc` | `POST /internal/soc/kill-switch` |
| Governed adapter execution | **By design hidden** | SOC console metadata only | Production `governed-adapter`; dev `dry-run` |

**FM-HIGHSCALE verdict:** **PASS (T1)** — customer intake, artifact metadata upload, authorization pack visibility, and SOC handoff links use real APIs; execution stays SOC-gated. **Remaining gaps (T2/T3, documented):** production governed adapter (external ops), cross-tenant SOC staff queue.

## FM-GOV — Notifications, audit, release evidence

Phase C classification (2026-07-05). Surfaces: `governance-pages.tsx` (`NotificationsPage`, `AuditPage`, `ReleaseEvidencePage`). Backend: `notifications.mjs`, `productionReleaseEvidence.mjs`, audit store.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Notification rules list | **Visible** | `#notifications` | `GET /v1/notifications` |
| Notification rule create | **Visible** | `#notifications` form (owner/admin) | `POST /v1/notifications` |
| Delivery retry / DLQ redrive | **Visible** | `#notifications` operations | `POST /v1/notifications/retries/process`, `…/dlq/redrive` |
| Tenant audit log | **Visible** | `#audit` (admin/owner/soc/auditor) | `GET /v1/audit-log` + filter/custody toggle |
| Release evidence inventory | **Visible** | `#release-evidence` (auditor+) | `GET /v1/production-release-evidence` |
| Release attestation snapshot | **Visible** | `#release-evidence` | `GET /v1/production-release-evidence/attestation` |
| Gap ledger export | **Visible** | `#release-evidence` copy JSON | Client-side from inventory + attestation |
| Release evidence record create | **Operator-only** | Documented boundary | `POST /v1/production-release-evidence`; operator validators/CLI |
| External notification delivery | **API-only** | Metadata-only ledger in dev | `ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook` production gate |

**FM-GOV verdict:** **PASS (T1)** — notifications (rules, retries, DLQ), audit log, and release-evidence read surfaces are wired to real APIs with RBAC-aligned visibility. **Remaining gaps (T2/T3, documented):** customer release-evidence write UI (operator CLI boundary), live provider delivery evidence (external ops).

## FM-STAFF — Internal admin

Phase C classification (2026-07-05). Surfaces: `StaffSurfacePage`, `TenantDetailView` (`detail-pages.tsx`). Backend: `internalManagement.mjs`, `signupIntake.mjs`.

| Feature | Classification | Staff UI | API / notes |
|---------|----------------|----------|-------------|
| Staff session gate | **Visible** | `#admin` empty state → staff login | `/internal/admin/login`; `principal=staff` |
| Signup queue approve/reject | **Staff-only** | `#admin` | `POST /internal/admin/signup-requests/:id/approve|reject` |
| Tenant directory + lifecycle | **Staff-only** | `#admin`, `#tenant-detail` | `GET/PATCH /internal/admin/tenants/:id` |
| Entitlement grants | **Staff-only** | `#admin`, `#tenant-detail` | `POST /internal/admin/tenants/:id/entitlements` |
| Support owner assignment | **Staff-only** | `#admin` | `PATCH /internal/admin/tenants/:id` `support_owner` |
| Internal approval decisions | **Staff-only** | `#admin` | `POST /internal/admin/approval-requests/:id/decision` |
| Internal audit log | **Staff-only** | `#admin` | `GET /internal/admin/audit-log` |
| Tenant user invite/disable | **Staff-only** | `#tenant-detail` | `POST …/users/:id/resend-invite`, `…/disable` |
| Staff SOC impersonation | **Staff-only** | `#internal-soc` | Staff `soc_analyst`/`soc_lead` → tenant SOC APIs |

**FM-STAFF verdict:** **PASS (T1)** — signup queue, tenant lifecycle, entitlements, approvals, support owner, and internal audit use `/internal/admin/*` on the staff surface only. **Remaining gaps (T2/T3, documented):** enterprise staff IdP/MFA on production internal host (external ops).

## FM-REPORTS — Builder, compliance kinds

Phase C classification (2026-07-05). Surfaces: `ReportsPage`, `ReportDetailPage` (`detail-pages.tsx`). Backend: `reports.mjs`, `custodyVerification.mjs`.

| Feature | Classification | Customer UI | API / notes |
|---------|----------------|-------------|-------------|
| Report list | **Visible** | `#reports` | `GET /v1/reports` |
| Report generate | **Visible** | `#reports` builder form | `POST /v1/reports` (`kind`, `title`) |
| Report detail | **Visible** | `#report-detail` | `GET /v1/reports/:id` |
| Export JSON + custody verify | **Visible** | `#reports`, `#report-detail` | `GET /v1/reports/:id/export?format=json` + `POST /v1/custody/verify` |
| Export Markdown/HTML | **Visible** | `#reports`, `#report-detail` | `GET …/export?format=markdown|html` |
| Compliance kinds (SOC2, ISO, DORA, NIS2, …) | **Visible** | Report kind selector | Supported kinds in `reports.mjs` |
| PDF export | **By design hidden** | Documented on `#reports` | Backend `json|markdown|html` only; intentional boundary |
| Immutable signed PDF storage | **Operator-only** | — | Release-gate / KMS boundary |

**FM-REPORTS verdict:** **PASS (T1)** — report list, generate, detail, JSON/MD/HTML export, and custody verification are wired to real APIs. **Remaining gap (documented):** PDF export/signing (intentional boundary).

## Verification

- Browser E2E: `scripts/react-portal-browser-e2e.mjs` — 38 routes + staff flows × 3 viewports
- Per-page audit: `.grok/skills/complete-portal/references/per-page-audit.md`
- PP-20 staff admin QA: `scripts/pp-20-admin-qa.mjs` — `/admin` + `#tenant-detail` L1–L3 PASS on `PORT=4320`
- Integration tests: `tests/integration/*`, `tests/e2e/ui-smoke.test.mjs`
- FM-AGENT QA: `GET /v1/agents` on `PORT=4320` — fleet table matches API `items[]`
- FM-CORE RBAC: `node --test tests/unit/react-portal-auth.test.mjs` — `canAccessRoute` gates notifications/audit/release-evidence per `roles.mjs`
- FM-VALIDATION helpers: `node --test tests/unit/checks-helpers.test.mjs` — check family/safety filters match `/v1/checks` catalog shape
- FM-WAF posture: `node scripts/pp-13-posture-qa.mjs` — WAF/discovery APIs + browser matrix with feature flags enabled
- FM-HIGHSCALE / FM-STAFF SOC: `node scripts/pp-14-high-scale-qa.mjs`, `node scripts/pp-15-soc-qa.mjs`
- FM-REPORTS: `node scripts/pp-16-reports-qa.mjs` — generate/export/custody verify