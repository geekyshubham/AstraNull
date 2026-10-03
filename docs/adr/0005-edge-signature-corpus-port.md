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

## Amendment 1 (corpus output version 3): runtime decision-flow port

### Context

Version 2 ported the data but not how either tool decides. In production:

- The signed outside-in path never gave cdncheck any addresses or CNAMEs, yet still reported
  `cdn_detected: false`. The UI showed "CDN not detected" for targets that were never checked.
- wafw00f block-page leaves were evaluated only when AstraNull's own heuristic said the marker
  response was blocked. Upstream evaluates them against the attack response unconditionally.
- Plugins were ranked by an AstraNull confidence score instead of the upstream checklist order.
- The worker result sanitizer dropped every array, which removed provider lists and evidence.
- The pinned transport's headers object exposed only `get()`, so header-name enumeration and
  Set-Cookie splitting never ran.

### Decision

1. **wafw00f evaluation.** `attack=False` leaves read the baseline response (`self.rq`).
   `attack=True` leaves read the scanner's existing benign combined-marker response
   (`self.attackres`), falling back to the single-class marker responses when the budget excludes
   it. A leaf is unknown only when its response was not captured.
   - The checklist order comes from pinned `wafprio.py`. `best` is the first match in that order;
     `all_matches` is the `-a` view.
   - The response read cap is upstream `MAX_RESPONSE_SIZE` (100 KiB, in memory only).
   - Set-Cookie uses requests' `", "` join/split.
   - `genericdetect` runs in upstream order over already-captured snapshots: no-User-Agent
     drift, then XSS / path / SQLi status drift, then Server header drift. A dropped connection
     means connection-level blocking.
2. **No new traffic.** AstraNull does not send wafw00f's payload strings. The benign markers,
   request budget, pinning, and SOC/ownership controls are unchanged.
3. **cdncheck.** The `cloud` category is ported (129,127 ranges, packed in
   `edgeCloudRangeData.mjs`).
   - The address check order is `cdn` → `waf` → `cloud`, and `CheckDNSResponse` order is
     AAAA → A → CNAME. Both are read from pinned `cdncheck.go`, and a single `cdncheck` verdict
     is reported alongside all typed matches.
   - Signed jobs pass the worker's already-vetted A/AAAA addresses (no extra lookups), plus a
     CNAME chain of up to 3 hops. Each hop is a counted, signed logical operation;
     `waf.fingerprint.safe` is now capped at 13 HTTP + 3 DNS operations.
   - CNAME matching stays a label-boundary suffix match. This is a strict superset of upstream
     public-suffix TLD / SLD.TLD equality.
4. **Evidence semantics.**
   - `cdn_detected` and `cloud_hosted` are `null` when DNS was not observed, and the projection
     reports that as inconclusive.
   - The worker sanitizer allows a fixed list of bounded edge-evidence arrays and still drops
     every other array.

### Deliberate deviations from upstream

| Upstream behavior | AstraNull | Why |
|---|---|---|
| Sends XSS/SQLi/LFI payload strings | Reuses bounded benign markers | No attack payloads against customer assets |
| Follows redirects | Redirect expansion stays disabled | Every hop would need its own signed accounting and scope check |
| Queries 1.1.1.1/8.8.8.8 | Worker resolver, vetted addresses | Connection pinning and egress policy |
| Header-name regex treated as a literal key (Shieldon never matches) | Regex applied | Matches the upstream intent |

## Addendum 1: curated edge-platform header layers

wafw00f types every header hit as a WAF and cdncheck types only addresses and CNAMEs, so edge
platforms identified purely by response headers (Vercel, Netlify, Azure Front Door, Google Cloud
load balancing, Bunny, KeyCDN, CDN77, StackPath, or a CloudFront/Cloudflare edge on an address
outside the vendored ranges) produced no CDN layer. `EDGE_PLATFORM_HEADER_SIGNATURES` in
`src/lib/edgeFingerprint.mjs` is a small hand-maintained list, separate from the generated
corpus, of vendor-unique header names or exact vendor `Server` tokens. Matches become `cdn`
layers with source `response_header`; they never set `waf_present`. Block-page signatures in
`src/lib/outsideInWafScanner.mjs` were also tightened to vendor-specific phrases after bare
substrings (`/f5/`, `/azure/`, "security policy") fingerprinted ordinary pages as WAF block pages.

## Addendum 2: CNAME CDN classification parity & ASN cloud provider port (asnmap)

### 1. CNAME CDN classification parity
Upstream cdncheck's `CheckSuffix` in `other.go` returned `true, discovered, "waf", nil` even though
the boolean return variable was named `isCDN`. AstraNull previously treated this strictly as `waf`,
which caused domains delegating via CNAME to CloudFront (`cloudfront.net`), Akamai (`akamaiedge.net`,
`edgekey.net`, `edgesuite.net`), Fastly (`fastly.net`), or Edgecast to be classified solely as WAF
without a CDN layer (`cdn_detected: false`).
- AstraNull now classifies known CDN CNAME suffixes as CDN layers (`cname_cdn_matches`), providing
  accurate CDN detection for CNAME-based edge deployments while preserving WAF protection layers.
- Expanded CNAME suffixes for modern edge platforms: Azure Front Door/CDN (`azureedge.net`, `azurefd.net`),
  Bunny CDN (`b-cdn.net`), KeyCDN (`kxcdn.com`), CDN77 (`cdn77.org`, `r.worldcdn.net`), Gcore (`gcdn.co`),
  StackPath (`hwcdn.net`), Vercel (`vercel-dns.com`), and Netlify (`netlify.app`).

### 2. ASN and Cloud Provider Engine (`asnmap` port)
While hyperscalers (AWS, GCP, Azure, Oracle Cloud) publish official CIDR JSON feeds, popular European
and boutique cloud and hosting providers (Hetzner, DigitalOcean, OVHcloud, Vultr, Linode, Scaleway,
Leaseweb, Contabo, Hostinger, UpCloud, Equinix Metal) do not publish synchronized official JSON ranges.
Relying solely on cdncheck static feeds left these providers unrecognized (`cloud_hosted: false`).
- AstraNull ports ProjectDiscovery `asnmap` semantics directly into Node.js (`src/lib/asnLookup.mjs`).
- Authoritative BGP origin routing tables from IRR/RADB are compiled via
  `scripts/generate-asn-cloud-data.mjs` into binary-packed hex interval tables (`src/lib/data/asnCloudData.mjs`).
- At runtime, IP-to-ASN and cloud provider lookup executes in memory via binary search (<0.1ms),
  requiring zero external subprocesses, zero network I/O, and zero third-party API keys.
- Optional live network hint via Team Cymru DNS TXT mapping (`origin.asn.cymru.com`) is supported for
  hermetic and operational resolution.
- Target detail views, protection summaries, and probe worker metadata now cleanly surface both CDN
  and hosting infrastructure (e.g. `AS24940 · Hetzner Online GmbH`).

