# Edge Fingerprint Source Attribution

`src/lib/data/edgeSignatureData.mjs` is generated data. Do not edit it by hand.
Its embedded `EDGE_SIGNATURE_CORPUS_MANIFEST` records runtime provenance. The adjacent
[`edgeSignatureData.manifest.json`](../../src/lib/data/edgeSignatureData.manifest.json) is the
independently hashable source manifest: it records the manifest/output versions, exact generator
hash, both upstream commits, all 172 plugin paths and file hashes, cdncheck input hashes, explicit
ported/excluded categories, and the generated module byte length/SHA-256.

## Pinned upstream sources

| Source | Exact revision | Ported input | License |
|---|---|---|---|
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | `69fbe3956bba47a172cf87e40e9037535d32a130` | All 172 `wafw00f/plugins/*.py` files except `__init__.py`: matcher calls plus `is_waf`/helper decision flow | BSD-3-Clause |
| [cdncheck](https://github.com/projectdiscovery/cdncheck) | `dac12984ef12fa5663c2b7591d0a304ef27c659b` | `sources_data.json` CDN/WAF CIDRs and `common` CNAME suffixes; `other.go` supplies the explicit CNAME item type | MIT |

Complete, unmodified notices are retained at:

- [`THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt`](../../THIRD_PARTY_NOTICES/wafw00f-BSD-3-Clause.txt)
- [`THIRD_PARTY_NOTICES/cdncheck-MIT.txt`](../../THIRD_PARTY_NOTICES/cdncheck-MIT.txt)

Pinned SHA-256 values:

| Input | SHA-256 |
|---|---|
| wafw00f plugin inventory (`sorted-path-length-content-length-v1`) | `44f4379d119d7cd688b2b8f68e5a1cd9e5bcf150491f46cb438d8a71f223b002` |
| wafw00f `LICENSE` | `fdaaf8393afcbab5a0db158ae742e76ec3803a7c72af19489f5bd521d3db08ea` |
| cdncheck `sources_data.json` | `4a7482b64ded7a611e11eadda6730cc8df159942c16713f17bbfecdb8a7cd2a3` |
| cdncheck `other.go` | `37182c8c3bc5a6182f2ced734d00fb252c5b0ae08cf284bd0437f44bc305244a` |
| cdncheck `LICENSE.md` | `cbcdaab87df3175107aa28915bd253cebdd618a49c9ac5d6c669c0b1cbebcacb` |
| `scripts/generate-edge-signatures.mjs` | `086f72d2f558de45fcdf79f7dd96c03d56e93e6218c43f108d2dc06cf69a83ed` |
| generated `src/lib/data/edgeSignatureData.mjs` | `94b18d931b0ecbc962098a1378297a8b189e3eed78a0c79b1b62981887145dd4` |

The standalone manifest also retains a SHA-256 for each of the 172 plugin files. cdncheck's
`cloud` category is explicitly accounted for but intentionally excluded: general hosting ranges
are not CDN/WAF edge-protection evidence.

## Faithful port policy

The generator uses Python's standard-library `ast` parser but never imports or executes upstream
plugins. It compiles each plugin's `is_waf` function and reachable helpers into a decision tree.
Matcher calls, helper alternatives, compound `AND`/`OR`, `NOT`, and early-return behavior therefore
remain detection gates instead of being flattened into independent positive signatures.

Generation fails closed when any of the following occurs: wrong git revision or input hash, an
omitted plugin, an unreachable helper, an unrepresented matcher call, unsupported statements or
expressions, an invalid/unsupported regex, invalid CIDR/CNAME data, or an inventory mismatch. At
the pinned revisions the output contains **172/172 plugins**, **518/518 matcher calls** (188 passive,
330 block-page), 2,462 CDN ranges, 1,071 WAF ranges, and 103 CNAME suffixes.

### Response tiers and private evidence

| Tier | Upstream source response | AstraNull rule |
|---|---|---|
| `passive` | wafw00f matcher uses its ordinary response (`attack=False`) | May be evaluated on any bounded response snapshot. |
| `block_page` | matcher uses wafw00f's attack response (`attack=True`, including defaults) | Leaf is **unknown**, not false, unless `blockResponse: true`. Three-valued decision evaluation prevents `NOT` or mixed branches from promoting unavailable evidence. AstraNull never sends wafw00f payloads to manufacture this response. |

`matchReason` remains an exact, case-sensitive equality check, matching upstream. Header-name regex
rules are evaluated against bounded enumerable header names. Set-Cookie evidence is capped at 16
values, 512 characters per value, and 4,096 characters total. It exists only in the in-memory
fingerprint input; classifier output contains signal labels, never raw header/cookie/body values,
and the scanner does not persist the private fingerprint fields.

### cdncheck CNAME semantics

At the pinned revision, cdncheck's `CheckSuffix` returns item type `"waf"` for every `common` CNAME
match. AstraNull embeds that explicit type on each generated rule/result. It does **not** infer a
CDN type from provider-key overlap. Consequently, CNAME-only `*.akamaiedge.net` (provider `akamai`)
and `*.cloudfront.net` (provider `amazon`) are reported as upstream type `waf`; CDN detection
requires an independently typed CDN address/CNAME signal. CDN and WAF address ranges are evaluated
independently. Combined results expose separate `waf_present`/`waf_providers` and
`cdn_detected`/`cdn_providers` fields; those provider lists come only from wafw00f matches or the
explicit cdncheck address/CNAME type, never from a provider-name heuristic. IPv4-mapped IPv6 inputs
receive the same range result as their mapped IPv4 address.

## Reproducible regeneration

Python 3 and Git are regeneration-time tools only; neither is a runtime dependency.

```bash
git clone https://github.com/EnableSecurity/wafw00f.git /tmp/astranull-wafw00f
git -C /tmp/astranull-wafw00f checkout --detach 69fbe3956bba47a172cf87e40e9037535d32a130

git clone https://github.com/projectdiscovery/cdncheck.git /tmp/astranull-cdncheck
git -C /tmp/astranull-cdncheck checkout --detach dac12984ef12fa5663c2b7591d0a304ef27c659b

node scripts/generate-edge-signatures.mjs \
  --wafw00f /tmp/astranull-wafw00f \
  --cdncheck /tmp/astranull-cdncheck \
  --out src/lib/data/edgeSignatureData.mjs \
  --manifest src/lib/data/edgeSignatureData.manifest.json

node --test tests/unit/edge-signature-corpus.test.mjs tests/unit/edge-fingerprint.test.mjs
```

Neither generated file contains a timestamp. The module and manifest are byte-reproducible for
identical pinned inputs, generator, and Node/Python JSON behavior. The manifest hashes the module;
it cannot be replaced together with hand-edited output without also violating the pinned generator
hash and per-input inventory checks. Increment the output version only when the generated format or
corpus behavior changes.
