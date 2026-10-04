# ADR-0013: Bounded worker activity is informational, never verdict evidence

Status: Accepted.

Customers need the actual operations behind a running check and a way to stop it. Deriving a plausible transcript from catalog phases, total request counts, elapsed time, or a verdict would invent evidence.

The existing signed external worker emits bounded structured activity over its authenticated job channel. Events bind to the tenant/run/target/check/nonce and the current lease. They are immutable across retries and readable only within the tenant. Telemetry uses the existing event store and retention with a separate item bound; it is excluded from verdict-evidence accounting and correlation. No raw payloads, credentials, reusable traffic scripts, new destinations, agents, or environments are introduced.

The table and console read the same recorded activity. Missing facts remain absent. Existing cancellation APIs revoke queued/leased work; worker lease acknowledgments cooperatively interrupt execution. Starting checks and high-scale governance retain all current ownership, SOC, rate, window, and concurrency gates.

Implementation and acceptance criteria: [Recorded probe activity](../backend/current-release-probe-activity.md).
