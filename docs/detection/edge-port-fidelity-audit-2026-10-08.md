# Edge port fidelity audit

The port is complete for its selected detection logic and data. The safe collector intentionally
implements a bounded subset of upstream network behavior. Those are separate claims.

| Layer | Verified coverage | Limits |
|---|---|---|
| wafw00f inventory | 172/172 plugins, 518/518 matcher calls, zero omitted/unsupported plugins | Pinned upstream revision `69fbe3956bba47a172cf87e40e9037535d32a130` |
| Plugin decisions | Exhaustive comparison of 6,774 possible complete-signal Boolean combinations against hash-verified upstream functions: zero mismatches | Missing responses use conservative three-valued logic; upstream false/None behavior is not copied when it could manufacture evidence |
| Regex translation | 443 patterns, 2,215 Python-vs-runtime witness/control comparisons: zero mismatches | Representative witnesses are not a mathematical proof for every possible Unicode string or response |
| Response semantics | Separate normal/block snapshots; AND/OR/NOT/helper/early-return flow; status/reason, bounded cookies, enumerable headers and priority order covered by focused tests | Regex-shaped header names implement the upstream intent; upstream treats those names literally |
| CDN/WAF/cloud data | Rebuilt the original pinned corpus byte-for-byte, then refreshed cdncheck to `a06260a272dc92cec0747f2f369b697088899bc7` | Versioned corpus v4: 2,491 CDN, 1,103 WAF, 116,097 cloud ranges; 103 common CNAME suffixes; Huawei CDN added |
| CDN engine | Typed address checks, IPv4/IPv6 and mapped addresses, AAAA/A/CNAME order and provider layers | Known upstream generic-CNAME/WAF and CloudFront/Fastly/ELB false-positive classifications are deliberately corrected |
| Technology hints | Curated response and CNAME detection covers observed CDN platform signals, including Framer and modern Fastly node names | cdncheck's `CheckWappalyzer` consumes a separate detector's technology labels; AstraNull does not add a general HTML/asset technology detector or assume an asset's CDN protects the tested hostname |
| Network collection | One pinned ordinary GET plus at most three counted CNAME operations; existing five-second deadline; independently completed typed DNS observations retained on deadline | No upstream attack-payload requests, arbitrary redirects/resolvers/retries or unrestricted active probing; marker/evasion/origin checks have their own approved profiles |

Reproduce the decision/regex audit offline after cloning the pinned wafw00f source:

```sh
node scripts/audit-edge-port-decisions.mjs /path/to/pinned/wafw00f
node --test tests/unit/edge-signature-corpus.test.mjs tests/unit/edge-fingerprint.test.mjs tests/unit/edge-fingerprint-scanner-integration.test.mjs tests/unit/probe-worker.test.mjs
```

The audit executes only hash-verified plugin function definitions against synthetic matcher truth
values, with no upstream network/request engine. The shipped Boolean decision evaluator is used
unchanged; signal truth values alone are instrumented. Regex comparisons use the shipped regex
compiler. The [recorded audit](edge-port-decision-audit-2026-10-08.json) identifies the pinned source.

Counts alone would not establish correctness. The exhaustive gate comparison, regex witnesses,
stream/cookie/header tests, signed-worker/accounting/persistence checks, and
[cross-site external observations](provider-fingerprint-verification-2026-10-08.json) provide
distinct evidence. A plugin that needs a block response can remain inconclusive on a healthy
ordinary GET. There is no claim of universal WAF detection or of WAF enablement/enforcement solely
from a CDN brand or network owner.
