# ADR-0031: Keyless Certificate Transparency source for passive subdomain import

Status: Accepted, 2026-10-15. Amends [ADR-0015](0015-passive-subdomain-import.md).

## Context

ADR-0015 made VirusTotal the only passive source for subdomain import. The hosted Compose stack
never forwarded `ASTRANULL_VIRUSTOTAL_API_KEY` to the control plane, so every deployment reported
`source.configured: false`. The portal then disabled "Discover and add subdomains" with only a
short note, and source failures (all 5xx) reached the banner as generic server-error copy behind
the still-open confirmation dialog.

## Decision

- `ASTRANULL_SUBDOMAIN_SOURCE` selects the source: `crtsh`, `virustotal`, or `disabled`.
  Blank means VirusTotal when a key is configured, and public Certificate Transparency logs
  through crt.sh otherwise. An unknown value, or `virustotal` without a key, stays visibly
  unconfigured with a typed `reason`. Nothing is called while unconfigured.
- The crt.sh source makes one bounded read per confirmed import (`q=%.<domain>`, unexpired,
  deduplicated, 30 s timeout, 8 MiB body cap, result cap from `ASTRANULL_SUBDOMAIN_MAX_RESULTS`).
  It keeps only certificate subject names that pass the existing strict-descendant
  normalization: wildcards, mailboxes, IPs and foreign names are dropped.
- Source failures map to typed codes (`subdomain_source_unreachable`, `_failed`, `_rate_limited`,
  `_auth_failed`, `_response_too_large`, `_not_configured`). The portal maps them to fixed
  copy (no server text), closes the dialog so the alert is visible, and states that no hosts were
  added. A zero-result import says so explicitly.

## Consequences

Still optional, passive and explicit: it runs only on a customer-declared FQDN after a reviewed
confirmation. It sends no traffic to the discovered hosts and adds no IP inventory discovery,
agents, environments or cloud access. Imported children keep the ADR-0015 ownership-inheritance
and ADR-0020 initial-detection rules. A certificate name shows that a certificate was issued for
it, not that the host is live, so imported hosts remain declarations until observed. The control
plane needs outbound HTTPS to `crt.sh`; the audit event records the source used.
