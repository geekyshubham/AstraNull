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
