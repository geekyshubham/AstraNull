# ADR-0005: Ported Edge Signature Corpus (wafw00f + cdncheck)

## Status

Accepted.

## Context

AstraNull's WAF fingerprinting and CDN detection previously relied on a hand-maintained
block-page rule list and a 52-entry product catalog. Upstream open-source projects maintain
significantly broader, community-verified corpora:

- **wafw00f** maintains 170+ WAF vendor fingerprint plugins.
- **cdncheck** (ProjectDiscovery) maintains curated CDN/WAF provider address ranges and edge
  CNAME suffixes.

Both are CLI tools (Python / Go). Shelling out to either at probe time would add a foreign
runtime per target, bypass tenant audit and rate bounds, and — for wafw00f — fire
XSS/SQLi/LFI/RCE payloads at customer targets, which AstraNull's governed probe path forbids.

## Decision

Port the **data**, not the control flow:

- `scripts/generate-edge-signatures.mjs` extracts wafw00f plugin signatures and cdncheck
  address/suffix tables into a generated, frozen module `src/lib/data/edgeSignatureData.mjs`.
- `src/lib/edgeFingerprint.mjs` classifies edge evidence against that corpus: passive
  header/cookie signatures on any bounded response snapshot, block-page signatures only
  against already-captured block evidence, and metadata-only IP/CIDR + CNAME classification.
- The outside-in WAF scanner stamps results with `edge_signature` and
  `edge_signature_corpus_version`; signed `waf.fingerprint.safe` probe jobs carry corpus
  version metadata through the existing catalog enrichment path.
- Upstream notices and licenses are retained in
  [`docs/attribution/edge-fingerprint-sources.md`](../attribution/edge-fingerprint-sources.md).

## Consequences

| Positive | Negative |
|---|---|
| 168 WAF vendors, 3.5k+ CDN/WAF ranges, 103 CNAME suffixes with zero new runtime dependencies. | Corpus must be regenerated manually when upstream changes. |
| No attack traffic: block-page tier is evaluated only on captured block evidence. | Block-page detection depends on an authorized bounded check having run. |
| Metadata-only classification; header values are allowlisted and truncated; nothing raw persists. | Upstream data quality issues (e.g. broad Google ranges in `cdn`) inherit into classifications; provenance is per-signal so operators can audit matches. |
| Deterministic, testable, and versioned (`EDGE_SIGNATURE_CORPUS_VERSION`). | Regex port from Python adds a small translation surface (guarded by generator compile checks). |
