# ADR-0002: Outbound-Only Agent Control

## Status

Superseded by ADR-0008 (2026-09-30). AstraNull is now outside-in only: the agent, its
control plane, and outbound-agent control are removed. Verdicts are produced from external
probe evidence only. See [ADR-0008](0008-outside-in-only-targets-first.md).

## Context

Enterprises do not want to open inbound management firewall ports for a validation agent.

## Decision

The AstraNull Agent will initiate outbound communication to the AstraNull control plane. Jobs are delivered over outbound WebSocket/long-poll/HTTPS polling.

## Consequences

| Positive | Negative |
|---|---|
| Easier deployment through enterprise firewalls. | Job delivery depends on agent connectivity. |
| No inbound management attack surface. | Agent must maintain reliable outbound channel. |
| Works in private networks with egress. | Offline agents cannot receive jobs. |

## Detection note

Outbound-only control does not prevent detection. The agent detects probes locally at its placement point and reports observations outbound.
