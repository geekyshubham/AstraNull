# ADR-0015: Optional passive subdomain import and separate detection

Status: Accepted, 2026-10-08.

Subdomain enumeration is an explicit action on one customer-declared FQDN. It queries the official
VirusTotal v3 API using a deployment-owned key, keeps only strict descendants of that hostname,
and imports bounded, deduplicated hostnames as ordinary child declarations. It is optional and
does not introduce IP inventory discovery, cloud access, agents or environments.

The confirmation explicitly approves the imported descendant scope. The returned list is reviewed
before a separate Detect unchecked hosts action starts any external fingerprint jobs. Import never
automatically queues detection. Each job uses the normal ownership, subscription, safe-window,
rate/concurrency, signed-worker, lease and kill-switch controls. The batch remains capped at 50;
known unverified hosts are skipped before dispatch so they cannot starve verified hosts.

Child membership uses `subdomain-of:<parent id>` tags. A child may inherit the parent's current
domain ownership proof only when both are active same-tenant FQDNs in the same retained execution
scope, the child is a strict descendant, and the parent is independently verified. Inheritance is
not recursive and does not grant a high-scale authorization. The UI exposes direct child-target
links and an inherited-proof label. Existing own-target verification remains valid independently.

The Subdomains tab reads the existing tenant-scoped APIs on demand. Read-only users can inspect
records; write and run actions are permission gated and reviewed separately. Missing source
configuration, source errors/quotas, partial inventory, skipped/deferred runs, loading and empty
states remain visible. Polling follows queued observations without dispatching more traffic.

WAF/CDN fingerprints are observations. A WAF fingerprint must never be labeled Protected, and
no matching edge fingerprint must never be labeled Exposed. Enforcement/capacity are separate
approved checks. Imported targets, fingerprints and audits use existing tables; no migration is
needed for this UI/flow completion. Child declarations remain accessible in Targets as well as
under their parent; no hidden group selection is introduced.
