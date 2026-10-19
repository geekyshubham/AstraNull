# ADR-0038: Deny assistant page reads before execution

Status: Accepted, 2026-10-19. Tightens ADR-0037 decision 3.

The runner previously checked `read_url_content` URLs in streamed tool events. Those events can arrive after a request starts, so the documentation-domain allowlist did not prevent the first request, redirects, or DNS changes.

Every step now installs a host-owned wildcard `PreToolUse` hook in its temporary workspace before starting `agy`. The hook permits only the exact `search_web` tool when the lease permits search. It denies all other tools, including every page read, even to an official documentation host. Insight jobs permit no built-in tools. Unknown/malformed hook payloads and oversized input are denied. Job-supplied tool names cannot expand the runner policy. This uses the CLI's documented [pre-execution hook contract](https://antigravity.google/docs/hooks).

The stream parser still terminates unexpected tool attempts as a second check. Sandboxing, plan mode, minimal environment, timeouts, tenant/RBAC-scoped data tools, audit events, secret redaction, and default-off deployment settings remain in place. The only files added to a job workspace are the owned `.agents/hooks.json`; the hook executable lives outside the model workspace. This adds no endpoint or database schema. Leases now advertise `allowed_tools: ["search_web"]`; no page-read URL is accepted from a model. Citations come from search results and answer text.

Verification: a native `agy` run attempted `read_url_content` against an owned loopback HTTP listener. The pre-tool hook returned `deny`, and the listener recorded zero requests. Unit tests also execute the installed hook command, reject malformed payloads and older expanded allowlists, allow search only for search-enabled jobs, and deny all tools for insight jobs. These checks do not enable the assistant or deploy changes.
