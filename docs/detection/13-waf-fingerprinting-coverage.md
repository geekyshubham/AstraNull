# WAF Fingerprinting and Coverage Detection

## Goal

Detect whether an approved web asset is behind a WAF/CDN, identify the vendor/product when possible, and classify coverage status.

## Supported public vendor/product names for catalog seed

| Vendor/product family | Detection mode |
|---|---|
| Cloudflare WAF/CDN | HTTP/DNS/TLS behavior + optional API. |
| Akamai / Akamai Kona Site Defender | HTTP/DNS/TLS behavior + optional API. |
| AWS WAF / AWS CloudFront / ALB/API Gateway associations | HTTP/DNS/TLS behavior + AWS API. |
| Azure WAF Application Gateway / Azure Front Door WAF | HTTP/DNS/TLS behavior + Azure API. |
| GCP Cloud Armor / Cloud CDN / external load balancer | HTTP/DNS/TLS behavior + GCP API. |
| Imperva / Incapsula | HTTP/DNS/TLS behavior + optional API. |
| Fortinet FortiWeb | HTTP behavior + optional API. |
| Barracuda WAF | HTTP behavior + optional API. |
| Fastly | HTTP/DNS/TLS behavior + optional API. |
| F5 BIG-IP ASM / Advanced WAF | HTTP behavior + optional API. |
| Palo Alto WAF/API security products | HTTP behavior + optional integration. |
| ModSecurity / OWASP CRS | Block-page/response behavior + optional headers. |
| Unknown/custom WAF | Generic WAF-present classification. |

## Fingerprint signal types

The table below is the platform-wide catalog of possible evidence, including connector snapshots and
future separately governed collectors. It is not the `waf.fingerprint.safe` signed-job operation
list. That job emits HTTP-derived fingerprint evidence only; its A/AAAA destination preflight is
reserved and attested as routing safety work, not stored as a DNS hint.

| Signal | Examples | Store |
|---|---|---|
| HTTP header names | CDN/WAF-specific safe header names. | Header names and hashed selected values only. |
| Cookies | Vendor-specific cookie name patterns. | Cookie names, no values. |
| Response status behavior | 403, 406, 429, 503, challenge redirect. | Code class and behavior flags. |
| Block page fingerprint | Vendor block/challenge page hash. | Hash and signature id, not full body. |
| DNS chain | CNAME to CDN/WAF domains, edge hostnames. | Normalized chain summary. |
| TLS/certificate | Edge cert issuer/SAN hints, SNI behavior. | Metadata summary. |
| ASN/IP ownership | CDN/WAF edge network hints. | ASN/provider label. |
| Redirect/challenge behavior | JS challenge, bot challenge, CAPTCHA. | Behavior label only. |
| Connector mapping | Provider resource says asset is attached to WAF policy. | Connector snapshot id + normalized fields. |

## Signed safe fingerprint algorithm

Provider detection uses `waf.fingerprint.safe` version 2.1.0, kind `waf_fingerprint_observation` ([ADR-0018](../adr/0018-provider-fingerprints-as-observations.md)).

1. Load the exact approved target from its signed job.
2. Reserve and attest bounded A/AAAA destination classification, reject unsafe addresses, and pin the accepted address set.
3. Collect at most three counted CNAME operations and one ordinary GET against the pinned endpoint, within the existing five-second job deadline. Redirect following and standalone TLS collectors stay disabled.
4. Compare the response's safe header/cookie names, bounded block-page fingerprints, vetted address set, and counted CNAME chain against the versioned provider corpus.
5. Record candidate providers, confidence, and observed evidence. Detection is E2 observation-only; it does not grade marker enforcement, origin lockdown, or capacity.
6. Reconcile optional configuration snapshots separately. Run marker, evasion, enforcement, and origin checks explicitly through their own approved profiles.

Legacy `outside_in_waf_scan` profiles remain readable/executable under their original bounds, and old verdicts are not rewritten. A current result needs a new versioned run.

## Confidence scoring

| Evidence | Suggested weight |
|---|---:|
| Strong connector mapping to asset and WAF policy | +0.35 |
| DNS CNAME chain to known CDN/WAF edge | +0.25 |
| Multiple vendor-specific HTTP headers/cookies | +0.20 |
| Block page/challenge fingerprint match | +0.25 |
| Edge ASN/provider match | +0.10 |
| Customer vendor hint matches evidence | +0.10 |
| Conflicting vendor signals | -0.20 |
| Direct origin response without edge | -0.25 |

Cap confidence to 1.0. Product version detection is optional and should have separate confidence.

## Coverage classification

| Inputs | Coverage status |
|---|---|
| WAF detected + blocking validation passed + no bypass | Protected. |
| WAF detected + validation missing but no failure | Unknown or Protected-unvalidated depending tenant policy. |
| WAF detected + marker/rate/scenario failed | Underprotected. |
| WAF detected + origin bypass confirmed | Underprotected. |
| WAF detected + connector says monitor/log/detect mode | Underprotected. |
| No WAF detected + WAF required | Unprotected. |
| No WAF detected + WAF not required | Excluded or Unknown depending policy. |

Recommended UI label: avoid overclaiming. Use `Protected` only when validation evidence exists. Otherwise show `Detected, not yet validated`.

## Product catalog schema

Each product catalog entry should contain:

| Field | Meaning |
|---|---|
| `vendor` | Normalized vendor id. |
| `product` | Display name. |
| `deployment_type` | cdn, cloud_native, appliance, reverse_proxy, custom. |
| `header_name_patterns` | Safe regex for header names only. |
| `cookie_name_patterns` | Safe regex for cookie names only. |
| `dns_patterns` | Known edge/CNAME domain suffixes. |
| `block_page_signature_ids` | Hash/signature ids. |
| `asn_provider_hints` | Optional provider hints. |
| `connector_provider_ids` | Matching connector providers. |
| `confidence_rules` | Weighted rule definitions. |
| `version` | Catalog version. |

## Evidence examples

### Protected and validated

```json
{
  "status": "protected",
  "detected_vendor": "cloudflare",
  "detected_product": "Cloudflare WAF",
  "confidence": 0.92,
  "signals": {
    "dns_chain_class": "cdn_edge",
    "header_signal_count": 3,
    "block_page_signature_id": "block_sig_cloudflare_generic_v1",
    "marker_blocked": true,
    "agent_observed_marker": false
  }
}
```

### Underprotected

```json
{
  "status": "underprotected",
  "reason_codes": ["marker_rule_not_blocking"],
  "detected_vendor": "akamai",
  "confidence": 0.81,
  "signals": {
    "waf_detected": true,
    "marker_expected": "block",
    "marker_observed": "allowed",
    "agent_observed_marker": true
  }
}
```

## False positive handling

| Problem | Mitigation |
|---|---|
| CDN without WAF | Separate `cdn_detected` from `waf_validated`. |
| Vendor header spoofing | Require multiple signals or connector confirmation. |
| App returns 403 itself | Use block-page fingerprint and agent non-observation. |
| WAF behind another CDN | Allow multiple edge/control layers. |
| Customer has allowlisted probes | Detect normal app response and warn that allowlisting invalidates validation. |
| Bot challenge blocks AstraNull | Mark inconclusive unless expected policy says challenge counts as pass. |

## Catalog breadth target

| Phase | Target |
|---|---|
| R1 seed | 15 major vendor/product families (table above). |
| R3 expansion | 50+ catalog entries via additional signatures and connector templates. |
| Ongoing | Quarterly catalog version with regression tests. |

Unknown vendors must still produce `waf_present` or `cdn_detected` with explicit confidence limits.

## Ported edge signature corpus (AstraNull WAF fingerprint + AstraNull edge classifier)

Beyond the versioned product catalog, AstraNull vendors a generated edge signature corpus:

- **WAF vendors:** 172 vendor signature sets ported from AstraNull WAF fingerprint plugin data (188 passive
  header/cookie signatures decidable from one ordinary GET; 330 block-page signatures evaluated
  only against block evidence an authorized bounded check already captured).
- **Address + CNAME:** signed jobs classify their vetted destination addresses and up to three counted
  CNAME lookups. They perform no additional A/AAAA or TLS hint collection. The separate, generated
  `asnEdgeData.mjs` snapshot covers dedicated Akamai (AS16625/AS20940), Cloudflare (AS13335), and
  Fastly (AS54113) CDN networks and AWS AS16509 cloud ownership missing from the upstream address
  data; it adds no runtime requests.
  Matches retain the actual matched ASN and `asn_dataset_version`. CDN ownership never establishes
  WAF enablement. The pinned cdncheck `waf` label on known CDN/generic cloud CNAMEs is retained as
  an upstream diagnostic but excluded from WAF providers and layers. `edgesuite.net` identifies
  Akamai, not Edgecast. Generic DNS/traffic-manager suffixes do not establish CDN presence.
- **Module:** `src/lib/edgeFingerprint.mjs` over the generated `src/lib/data/edgeSignatureData.mjs`;
  scanner results carry `edge_signature` and `edge_signature_corpus_version`, and signed
  `waf.fingerprint.safe` probe jobs carry corpus version metadata.
- **Projection:** `src/lib/edgeDetectionProjection.mjs` is the single source of truth that turns a
  signed probe result into the WAF/CDN answer. The API, the durable row, and the portal all read it,
  so they cannot disagree. `src/lib/edgeDetectionPresenter.mjs` renders a stored row for the API.
- **Persistence:** each resolved detection upserts one current row per target into
  `target_edge_detections` (migration `0052`), keyed `(tenant_id, target_id)`. The row records WAF
  and CDN status/provider/type independently, both typed provider lists, confidence, corpus version,
  and label-only evidence. Target detail and target-group responses expose it as `edge_detection`.
- **Provenance, licenses, and regeneration:** [edge-fingerprint-sources](../attribution/edge-fingerprint-sources.md);
  decision record in [ADR-0005](../adr/0005-edge-signature-corpus-port.md).

Classification from the corpus never sends traffic by itself and never manufactures block
evidence; per-signal provenance is retained so operators can audit any vendor match.

An ordinary GET that already received a vendor-specific denial can supply block-page evidence
without a marker request. A bare 403 or ordinary redirect cannot. With zero marker attempts,
effectiveness is inconclusive and protection is `detected_only` for a matched WAF or `inconclusive`
for a fingerprint miss; it cannot be `unprotected`. Historic stored fingerprint misses receive
this corrected presentation without changing signed events or custody. See the
[Barclays diagnosis](../backend/waf-cdn-detection-repair-2026-10-08.md).

Generic CloudFront/ELB fingerprints and header-name-only catalog candidates do not establish WAF
presence. The AWS managed-rule custom-response header can establish an AWS WAF fingerprint.
Framer edge-hosting and both Fastly cache-node header formats have separate CDN signatures.
Typed positive DNS provider evidence survives an HTTP deadline as an explicitly partial,
inconclusive observation; WAF remains unknown and effectiveness untested.

## Done criteria

- Product catalog is versioned and testable.
- Catalog breadth milestones are tracked in the WAF backlog.
- Fingerprinting stores only metadata.
- Detection supports multiple candidates and confidence, not just binary WAF yes/no.
- UI explains why product was detected.
- Classification separates WAF detected from WAF validated.
