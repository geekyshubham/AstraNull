# ADR-0040: OpenAI-compatible model backend for the assistant runner

Status: Accepted, 2026-10-21. Extends [ADR-0037](0037-ai-remediation-assistant-runner.md); the [ADR-0038](0038-assistant-pre-execution-tool-gate.md) gate applies to the `agy` backend only.

## Context

The runner answers jobs by spawning the local `agy` CLI, which ties the assistant to one desktop sign-in. The product owner runs a local gateway that exposes an OpenAI-compatible `POST /chat/completions` API serving the reasoning model `deepseek-v4-flash`. That model returns its chain of thought in `message.reasoning_content` and the answer in `message.content`.

## Decision

1. **Second backend, same loop.** `ASTRANULL_ASSISTANT_RUNNER_BACKEND` is `agy` (default) or `openai`. Prompt construction, untrusted-data fencing, the `astranull-tool` fence protocol for the 13 read-only data tools, per-step timeout, 240 s deadline, tool budget, final no-tools step, sanitisation and result posting are unchanged. Only the "run one model step" primitive differs (`runAssistantJob` takes it as a parameter; `runAgyJob` keeps its signature).
2. **Request.** One call per step to `{base}/chat/completions` with bearer auth, a single user message, `stream: false` and `max_tokens` (default 8192, bounded 1024 to 32768) that leaves room for reasoning. No `tools` or `functions` are sent, so the model can only use the fence protocol, which the control plane authorises per tenant and role. Redirects are refused so the key cannot leave the configured host.
3. **Output.** Only `content` is used. `reasoning_content` is never read, stored or forwarded; a leading inline `<think>` block is stripped. Empty `content` is retried once within the same step timeout, then fails as `llm_empty_response`.
4. **Failure mapping.** 401/403 to `llm_auth_failed`, 429 to `llm_rate_limited`, 5xx to `llm_unavailable`, other statuses to `llm_failed`, aborted calls to `llm_timeout`, network errors to `llm_unreachable`, malformed bodies to `llm_bad_response`. Results carry only the code; upstream bodies, prompts and keys are never copied.
5. **Configuration.**

   | Variable | Meaning |
   |---|---|
   | `ASTRANULL_ASSISTANT_LLM_BASE_URL` | Required. `https`, or `http` only for loopback hosts. No credentials, query or fragment. |
   | `ASTRANULL_ASSISTANT_LLM_API_KEY_FILE` | Path to a key file (mode 0600, read once, trimmed). Preferred. |
   | `ASTRANULL_ASSISTANT_LLM_API_KEY` | Alternative to the file. |
   | `ASTRANULL_ASSISTANT_LLM_MODEL` | Default `deepseek-v4-flash`. |
   | `ASTRANULL_ASSISTANT_LLM_MAX_TOKENS` | Optional, 1024 to 32768. |
   | `ASTRANULL_ASSISTANT_LLM_TIMEOUT_SECONDS` | Optional cap, 5 to 240, applied under the lease timeout. |

   The key is never logged, placed on argv, or included in job payloads or results. The startup log shows the backend, model and endpoint origin only.
6. **Control plane.** `ASTRANULL_ASSISTANT_RUNNER_BACKEND=openai` on the control plane defaults the configured model to `deepseek-v4-flash` and reports `capabilities.web_search: false`. Any model name matching the existing pattern remains valid through `ASTRANULL_ASSISTANT_MODEL`. The runner reports the model it used and the control plane shows that name on the answer. The portal contains no hard-coded model or provider text and only shows "Searched the web" when an answer lists searches.

## Consequences

- Customer finding, target and tool-result data is sent to whichever model provider the gateway routes to. No data processing agreement is in place with that provider, so this is acceptable only for the current internal phase and demo data, and a contracted provider is needed before general availability. Redaction and untrusted-data fencing still apply.
- Web search is unavailable on this backend. Jobs that request it still answer; the runner tells the model that search is unavailable so it does not invent citations, and answers carry no searches or sources.
- The ADR-0038 pre-execution gate does not apply because the backend has no built-in tools; the model cannot act beyond returning text, and data tool calls still pass through the control plane RBAC, audit and budget.
- Reasoning models spend tokens before answering, so steps are slower and a too-small `max_tokens` shows up as `llm_empty_response`.
- The `agy` backend remains the default and is unaffected.

## Update 2026-10-22: runner on the AWS host

The runner no longer has to run on a developer machine. It runs as the `assistant-runner` container on the production EC2 host and calls OpenCode Go (`https://opencode.ai/zen/go/v1`, model `deepseek-v4-flash`) directly.

1. **Deployment.** `ops/aws/docker-compose.yml` defines `assistant-runner` from the core worker image (`ASTRANULL_CORE_WORKER_IMAGE_ID`), non-root, `restart: unless-stopped`, started after a healthy `control-plane`, with a heartbeat-file healthcheck. `deploy.sh`, `restore.sh` and `release-state.sh` treat it like the other core workers: start, stop/remove, absence verification, image identity, health and rollback. `scripts/validate-aws-compose-secrets.mjs` requires it, pins it to the core image group and rejects any environment key outside the runner allow-list (no database, SMTP, OIDC or probe secrets). During reconcile, an absent `assistant-runner` is tolerated once so the first release that adds it can recover prior state; a present one must match the canonical image ID and be healthy.
2. **Idle, never crash-looping.** If the runner token, backend selection or `openai` backend settings (base URL, API key, headers) are missing or invalid, or the `agy` backend is selected but no `agy` executable exists, the runner logs one line naming the reason (never a value) and idles. It refreshes `ASTRANULL_WORKER_HEARTBEAT_FILE` while idle and on every poll cycle, so the container stays healthy and settings are applied by recreating the container.
3. **Static headers.** `ASTRANULL_ASSISTANT_LLM_HEADERS` is an optional JSON object of at most 8 string headers. Names must be RFC 7230 tokens, values printable ASCII of 1 to 256 characters, duplicates (case-insensitive) and `authorization`, `host`, `content-type`, `content-length`, `cookie`, `transfer-encoding` and `connection` are rejected. Header values are never logged. OpenCode Go answers `400 MissingSessionID` without a stable `User-Agent` and `x-opencode-session`, which this carries (`astranull-assistant-runner/1.0`, `astranull-production`).
4. **Applying settings.** `configure-assistant.yml` and `ops/aws/configure-assistant.sh` write the assistant keys to `ops/aws/.env` under the deploy lock and then recreate only `control-plane` and `assistant-runner` (`up -d --no-deps --force-recreate --wait`) on the currently deployed release image IDs from the canonical release bundle. They no longer re-run `deploy.sh` for the same SHA, which refuses a same-tag rebuild. The LLM API key and runner token travel only on stdin, never argv or logs. The base URL is not a free-form dispatch input: the workflow maps the `llm_provider` choice (`opencode-go`) to `https://opencode.ai/zen/go/v1`, and the wrapper independently accepts only that exact URL (or empty), so a dispatcher cannot redirect the key or customer data to another host. The runner itself keeps the generic rules (https, or http for loopback) so local gateways still work, and refuses redirects.

### Data flow and risk acceptance

Customer finding, target and tool-result data (after existing redaction and untrusted-data fencing) now flows from the EC2 host to OpenCode Go. No data processing agreement exists with that provider. The product owner has accepted this for all tenants. Consequences: the processing location and sub-processors are outside our contract set, the API key is a production secret in the host `.env` (rotate on suspicion of exposure and when the operator changes), and a contracted provider remains required before general availability for regulated customers (GDPR Article 28, SOC 2 vendor management, ISO 27001 A.5.19 to A.5.23). Turning the assistant off (`enabled=0`) blanks the token and key and idles the runner.
