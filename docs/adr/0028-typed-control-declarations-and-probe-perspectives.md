# ADR-0028: Typed control declarations and probe perspectives

Date: 2026-10-13

Status: Accepted

## Context

Customer setup keys such as `declared_forbidden_tcp_port`, `expected_block_behavior`, and `syn_protection_declaration` were labels on catalog checks. Nothing in the portal or API wrote a declared WAF block signature, so probes that already knew how to match `probe_profile.declared_block_signature` never received one (review F04, F18). Network checks defaulted to “must block before origin” with no per-port allow or deny. Rate-limit and canary-sink checks had no customer-supplied threshold or HTTPS sink (F22). A single unpublished probe source made allowlist and geo rules indistinguishable from deny-all or allow-all (F12). Origin IPs already live on origin bindings (F13); this decision does not duplicate them.

Correlation can only treat a declaration as an input when it is typed, validated, tenant-scoped, and present on the signed probe job. Perspectives with published egress IPs are required before an allowlist or geo rule can be graded.

## Decision

1. Store typed control declarations at `target.metadata.control_declarations` (version 1). The key is reserved from free-form metadata; a metadata-only patch preserves stored declarations. Writers use `PUT /v1/targets/:id/control-declarations` (`target_group:write`); readers use `GET` (`target_group:read`). Cross-tenant reads and writes return 404. Validation rejects unknown keys, duplicate network rules, invalid ports, non-token header names, non-HTTPS canary sinks whose host is not the target (or a subdomain of it), and perspective ids missing from the registry.
2. Persist in existing JSON metadata: the dev JSON store `target.metadata` object and Postgres `targets.metadata_json`. No schema migration.
3. `createProbeJob` copies `probeDeclarationsSubset` onto `probe_profile.declarations`, maps `waf.block_signature` onto `probe_profile.declared_block_signature` (contract fields plus the `header` / `status_code` shape existing graders already read), and maps vetted `network_policy` ports onto `probe_profile.declared_ports` for `port_scan_bounded`.
4. Probe perspectives come from `ASTRANULL_PROBE_PERSPECTIVES` (JSON array of `{id,label,region,asn,egress_ips}`). Missing env yields `{ id: "default", label: "Primary", egress_ips: [] }`. Malformed config fails closed at process start. `GET /v1/probe-perspectives` lists id, label, region, and egress_ips so customers can allowlist or deny sources.

## Consequences

Declarations become inputs to correlation and grading instead of unused catalog labels. A customer-set block header can identify WAF products that have no vendor signature. Per-port allow/deny is available for violation-only NFW verdicts. Allowlist and geo checks can compare observed source perspectives against a published registry. PUT is audited with a before/after summary that records header name and value length, never the value. Targets with no declarations keep previous probe-job shape.
