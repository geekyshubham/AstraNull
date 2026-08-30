# ADR-0005: Faithful Port of the wafw00f + cdncheck Edge Corpus

## Status

Accepted; production-quality port revised at corpus output version 2.

## Context

AstraNull needs broad WAF/CDN evidence without cloud credentials, automatic inventory discovery, or
unmanaged traffic. wafw00f and cdncheck maintain useful corpora, but running either tool against a
customer target would violate the bounded no-access-first path: wafw00f actively submits attack
payloads, and runtime Python/Go subprocesses would bypass AstraNull's signed-job controls.

The first data port extracted matcher calls with regular expressions and treated every call as an
independent vendor signal. Review demonstrated that this was not faithful:

- helper schemas and compound `AND`/`NOT` control flow were flattened, creating false positives;
- four compound plugins (`applicationgateway`, `kemp`, `reflected`, `threatx`) were silently omitted;
- cookie regexes were evaluated against names after `Set-Cookie` syntax had been discarded;
- regex-shaped header names could not be captured;
- reason phrases used substring/case-insensitive matching instead of upstream exact equality;
- CNAME type was guessed from provider overlap even though pinned cdncheck explicitly returns
  `waf` for `common` suffix matches;
- IPv4-mapped IPv6 did not share IPv4 range behavior; and
- source revisions, input hashes, and complete license notices were not embedded/retained.

## Decision

Port data and decision semantics, never upstream traffic behavior:

1. Pin wafw00f at `69fbe3956bba47a172cf87e40e9037535d32a130` and cdncheck at
   `dac12984ef12fa5663c2b7591d0a304ef27c659b`.
2. Parse wafw00f with Python's standard-library AST without importing/executing it. Emit all 172
   plugins, all 518 matcher calls, and a decision tree preserving helpers, early returns,
   `AND`/`OR`/`NOT`, and explicit/default `attack` selection. Any omission or unsupported syntax is
   a generation error, not a warning or skipped vendor.
3. Treat block-page leaves as unavailable until the caller supplies explicit captured block
   evidence. Evaluate unavailable leaves with three-valued logic so negation cannot produce a
   match from missing evidence. A result also requires at least one positive observed signal.
4. Keep `matchReason` exact and case-sensitive. Enumerate bounded headers for regex header names.
   Retain bounded Set-Cookie strings only in transient classifier input (16 values, 512 characters
   each, 4 KiB total); never return or persist raw values.
5. Preserve cdncheck categories independently. Address hits retain their `cdn` or `waf` family.
   Each CNAME rule/result embeds the item type parsed from pinned `other.go`; at this revision that
   type is `waf`, including Akamai/CloudFront suffixes. Top-level WAF/CDN statuses and provider
   lists are derived only from those typed signals or direct wafw00f matches, never provider names.
6. Normalize IPv4-mapped IPv6 to its IPv4 numeric address before CIDR lookup, matching Go/net
   behavior used by cdncheck.
7. Emit both an embedded runtime provenance record and a standalone deterministic source manifest.
   The standalone manifest contains every plugin path/file hash, exact input and generator hashes,
   source commits, output/manifest versions, explicit category exclusions, and generated module
   byte length/SHA-256. Preserve exact complete BSD-3-Clause and MIT texts in
   `THIRD_PARTY_NOTICES/`.

## Consequences

| Positive | Trade-off |
|---|---|
| Compound/helper truth tables gate vendor promotion, eliminating flattened false positives and restoring four omitted plugins. | Regeneration requires Python 3 plus Git, though application runtime remains Node-only. |
| Pinned commits, strict hashes, exact inventories, and timestamp-free output make the corpus auditable and reproducible. | Upstream updates require an intentional pin/hash/output-version review. |
| Passive and already-captured block evidence compose without adding attack traffic or discovery. | A block-only or mixed matcher remains unresolved when no authorized block response exists; this safe false negative is deliberate. |
| Cookie/header/reason semantics match the pinned source while private values stay bounded and out of results. | Regex compatibility is a reviewed translation surface; unsupported Python regex constructs fail generation. |
| CDN/WAF type provenance remains explicit even where cdncheck's CNAME classification is counterintuitive. | CNAME-only Akamai/CloudFront is `waf`, not `cdn`, at this pin; consumers must not reinterpret provider names. |
| IPv4 and mapped-IPv6 range inputs now agree. | General cloud ranges remain excluded because they answer hosting, not edge protection. |

No route, service, or probe obtains permission to target undeclared assets from this decision. The
classifier remains pure metadata evaluation; customer declaration, ownership proof, signed jobs,
rate bounds, and SOC gates continue to live in their existing control paths.
