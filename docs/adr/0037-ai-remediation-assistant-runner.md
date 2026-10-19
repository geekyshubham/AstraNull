# ADR-0037: AI remediation assistant through an agy runner

## Status

Accepted. Requested by the product owner on 2026-10-19 ("use agy sdk for it and configure one of the accounts from VibeRouter"). Implements ADR-0034 decision 5 with a different execution topology.

## Context

ADR-0034 deferred a finding-grounded assistant that tells a customer what is missing and how to fix it for their CDN, WAF, firewall or cloud vendor, modelled on the CheckRed DNSPM chat. That design ran the Antigravity CLI (`agy`) inside the control plane. Production runs as a non-root Alpine container on EC2, while `agy` is a desktop binary whose Google sign-in lives in the operating-system user's home directory and is switched by the VibeRouter app. Baking the binary and a personal sign-in into the production image is not workable, and copying the sign-in to the server would move a personal credential into production infrastructure.

## Decision

1. **Queue in the control plane, execute in a runner.** The control plane validates requests, resolves the finding and target server-side for the caller's tenant, builds the prompt, and stores the job in server memory with a one-hour TTL. A separate `workers/assistant-runner.mjs` process runs on any host where `agy` is signed in (the account VibeRouter has active), leases jobs, runs `agy`, and posts the answer back. The Google sign-in never leaves that host.
2. **Runner channel.** Runner routes (`/internal/assistant/runner/*`) authenticate only with a bearer token from `ASTRANULL_ASSISTANT_RUNNER_TOKEN` (at least 32 characters, constant-time compare). They return 404 when the assistant is disabled or no valid token is configured, and failed attempts are audited without the token.
3. **Constrained execution.** Each job runs `agy -p … --output-format stream-json --mode plan --sandbox --disable-slash-commands` in a temporary workspace with a minimal environment and a hard timeout. Per [ADR-0038](0038-assistant-pre-execution-tool-gate.md), a host-owned wildcard `PreToolUse` hook permits only `search_web` for search-enabled jobs and denies every other built-in tool before execution. All page reads are denied, including vendor documentation URLs; the earlier post-start URL check was insufficient. Insight jobs deny all built-in tools. The streamed-event check still kills unexpected attempts as a second check. `--dangerously-skip-permissions` is never passed.
4. **Data handling.** Finding, target and user text are redacted for credentials and secrets and wrapped as untrusted data before they reach the model. The prompt forbids attack payloads, bypass or evasion steps, and claims that anything is fixed. Answers are sanitised on ingestion and rendered by a React-only markdown renderer that never injects HTML and only links http(s) URLs.
5. **Governance.** Default off. `ASTRANULL_ASSISTANT_ENABLED` turns it on for a deployment and `ASTRANULL_ASSISTANT_TENANTS` opts tenants in (the explicit demo tenant is included when enabled). Every job is audited as `assistant.job_created` with identifiers and counts only, never message text. Per-user and per-tenant rate limits apply. Conversations live in the browser (`localStorage`), as in the DNSPM chat; the server keeps only the ephemeral job.
6. **Advice only.** The assistant never changes verdicts, findings, readiness or configuration, and offers no actions beyond text.

## Data tools and visuals

Added 2026-10-19 at the product owner's request ("it was able to interact with the database … even the data that we are not showing on the UI"), matching the CheckRed chat.

1. **Page context.** Every portal page sends a bounded `context.page` (route, title, kind, tab, entity, filters, facts) with each question. The server sanitises it strictly, drops unknown keys, and re-reads any named entity within the caller's tenant; only entities found that way are presented as verified. Filters and facts are what the page displayed and are fenced as untrusted page facts, never trusted as truth.
2. **Read-only, tenant-scoped data tools.** The model may ask for one of 13 tools (`list_targets`, `get_target`, `list_findings`, `get_finding`, `list_runs`, `get_run`, `list_checks`, `get_check`, `get_readiness`, `get_edge_coverage`, `list_schedules`, `list_audit_events`, `query_data`) by replying with an `astranull-tool` fence. The runner forwards the call to `POST /internal/assistant/runner/jobs/:id/tool`, and the control plane executes it with the asking user's captured tenant, role and scopes, reusing the same service functions as the `/v1` routes. There is no SQL, no free-form query and no write path. `query_data` aggregates only allow-listed datasets, group-by fields and filters.
3. **RBAC and audit.** Each tool, and the server-side enrichment of a page entity, needs the same permission and scope check (`requirePermission`) as its `/v1` route (`list_audit_events` needs `audit:read`). A denied call returns `{ error: "permission_denied" }` to the model and is audited as `rbac.denied`. Every call is audited as `assistant.tool_called` with only the tool name and job id. At most 8 calls per job, and the captured context is discarded when the job ends.
4. **Results are data.** Tool output is secret-redacted, capped at 12,000 characters and fenced as untrusted data. The model never receives credentials, the runner token or other tenants' data, and the runner host never connects to the database.
5. **Visuals.** `query_data` registers each table as `Q1`, `Q2`, …; the answer places `[[data:Q1]]` or `[[data:Q1|bar]]` (table, bar, line, donut) where a chart belongs. The server drops markers for ids it did not register and returns only referenced tables in `response.data_results`, which the portal renders without injecting HTML.
6. **Agent loop.** The runner re-runs `agy` statelessly with the transcript plus each tool result, under the same sandbox flags, allow list, per-step timeout and an overall 240-second deadline. Once the tool budget is spent it runs one last step that must answer without tools.

## AI insights

Added 2026-10-19 at the product owner's request ("just like what we had with AI insights in the DNSPM … on each page or even in the details … an AI insights button"), matching the CheckRed DNSPM page insights.

1. **Computed first.** `POST /v1/assistant/insights` builds a board for the open page or record (verdict, up to 5 KPIs, up to 6 chart or table sections, up to 5 actions) from the same read-only service functions as the data tools, with the caller's tenant, role and scopes. Datasets the caller cannot read are skipped silently, without `rbac.denied` noise, and listed as unavailable. Every number on the board is computed server-side.
2. **Narrative second.** When the runner is online, the server queues an insight job whose prompt holds only the board, fenced as untrusted data, and asks for a JSON `{ summary, takeaways }`. The job leases with no allowed tools (no web search, no page reads, no data tools), a 90-second limit and its own per-user rate limit. The parsed briefing is stripped of markdown and links, secret-redacted and capped. Anything unparseable fails the job, and the portal keeps the computed summary.
3. **Entry points.** The portal topbar shows "AI insights" on every customer page, scoped to the route and its record. Target, finding and evidence views carry inline entries. A finding group publishes its member finding ids, because the route alone cannot name them. Action links are limited to in-portal hash routes.
4. **Governance.** Insights follow the assistant switch (`ASTRANULL_ASSISTANT_ENABLED` and tenant opt-in). Narrative jobs are audited as `assistant.job_created` with `purpose: insight` and the page kind only.

## Consequences

- The assistant is available only while a runner is connected; the portal shows a setup state when no runner has polled in the last 60 seconds.
- Customer finding context is processed by the Google account active in VibeRouter on the runner host. That is an accepted product-owner decision for this phase; a hosted model gateway with a data-processing agreement would be needed before general availability.
- Jobs are lost if the control plane restarts. Production runs one control-plane instance, so the in-memory store is sufficient now; more than one instance needs a shared job store.
- Answers come from a model with open web search and can be wrong or stale. The UI labels them as advice to verify with the provider, followed by a re-run of the check.
- Data tool results for the asking user's tenant reach the same Google account as finding context. They are limited to what the user's role can already read in the portal, plus detail fields the UI does not show.
