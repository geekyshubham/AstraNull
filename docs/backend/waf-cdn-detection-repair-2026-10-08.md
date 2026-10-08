# WAF/CDN detection repair: Barclays

## Recorded failure

Target `tgt_c041d56e5f3b4517` is the declared FQDN `barclays.com`. On deployment
`a845930fdf232bc66efde8143d220d9511e67593`, signed run `run_3493aea555fe2460`
(2026-10-08 04:48 UTC) completed a v2.0.0 fingerprint observation in 72 ms:

- Ordinary GET: HTTP 302, zero marker probes, no matching HTTP fingerprint.
- Vetted address: `69.192.16.127`; CNAME result: only `barclays.com`.
- Both WAF and CDN reported `not_detected`; stored protection incorrectly said `unprotected`.

An independent ordinary GET returned HTTP 302 to `https://home.barclays/`, without a vendor
header. This redirect does not authorize probing its different hostname. Local DNS returned
`23.47.231.231`; `www.barclays.com` returned `www.barclays.com.edgekey.net` (a different target,
used as corroborating public DNS evidence only). Both addresses map to AS16625 in
[RIPE RIS network info](https://stat.ripe.net/data/network-info/data.json?resource=69.192.16.127).
The recorded IP's PTR is `a69-192-16-127.deploy.static.akamaitechnologies.com`; the Team Cymru
TXT result independently identifies `16625 | 69.192.16.0/20 | US | arin | 2008-02-26`.

Conclusion: **Akamai CDN network observed. WAF enablement/vendor and effectiveness unverified.**
No enforcement, origin lockdown or capacity conclusion follows from this observation.

## Port gaps and corrections

1. The pinned cdncheck CDN ranges did not contain either Akamai address. The ASN registry knew
   Akamai but the offline lookup populated only hosting providers, so it could not use that fact.
   A separately generated, content-hashed RIPE RIS snapshot now includes current dedicated Akamai,
   Cloudflare and Fastly network prefixes, plus AWS cloud ownership (AS16509). Lookup preserves the actual matched ASN/family.
   It adds no worker DNS/HTTP operations and never turns CDN ownership into a WAF claim.
2. Pinned cdncheck labels all common CNAME matches `waf` in
   [CheckSuffix](https://github.com/projectdiscovery/cdncheck/blob/dac12984ef12fa5663c2b7591d0a304ef27c659b/other.go).
   That diagnostic remains available; known CDN and generic cloud/DNS suffixes no longer populate
   canonical WAF layers. The duplicate `edgesuite.net` Edgecast attribution is suppressed in the
   canonical result. Generic traffic-manager/DNS suffixes and generic cache headers no longer
   identify CDN products by themselves.
3. An already-observed vendor-specific denial on the ordinary GET now supplies block-page
   fingerprint evidence even with zero markers. Generic 403s and ordinary pages do not.
4. Zero marker attempts now leave effectiveness inconclusive and cannot produce `unprotected`.
   Presence-only WAF results use `detected_only`. Historical stored misses receive safe presentation
   without rewriting signed events or custody. New detection needs a new v2.1.0 run.
5. Target detail now preserves bounded ASN and curated CNAME evidence, including the ASN snapshot
   hash. The existing JSONB evidence columns suffice; no migration is needed. API documentation
   and response-shape checks cover the additive fields.

The wafw00f port remains a bounded observation implementation, not an invocation of the upstream
attack scanner. Its [Akamai plugin](https://github.com/EnableSecurity/wafw00f/blob/69fbe3956bba47a172cf87e40e9037535d32a130/wafw00f/plugins/kona.py)
looks for `Server: AkamaiGHost`; the reported redirect exposed no such header. It would be
incorrect to infer Kona enablement solely from the CDN address.

## Validation and rollout

Expanded verification covered apex and www hostnames for Qantas, Westpac and Jagex, and repeated
the www observations from the production probe worker's network. These were operator public
HTTP/DNS diagnostics, not signed platform runs or ownership-bypassing dispatches. See the
[metadata-only observation record](../detection/provider-fingerprint-verification-2026-10-08.json).

| Host | Observed provider signals | HTTP | WAF conclusion |
|---|---|---|---|
| qantas.com / www.qantas.com | Akamai addresses and www edgekey/akamaiedge CNAMEs | Five-second timeout from both locations | Unknown; retain DNS CDN evidence as partial |
| westpac.com.au / www.westpac.com.au | CloudFront headers/address/CNAME; www also exposed Fastly cache-node headers from the AWS location | Apex 301; www 200 | CloudFront/Fastly CDN and generic ELB fingerprints do not prove WAF enablement |
| jagex.com | Framer server fingerprint, AWS AS16509 address ownership | 308 | No WAF-specific fingerprint; Framer edge hosting observed |
| www.jagex.com | Cloudflare headers, CNAME, address ownership | 200 | Cloudflare fingerprint observed; enforcement remains untested |

Framer's own [hosting infrastructure documentation](https://www.framer.com/help/articles/guide-to-framer-hosting-infrastructure/)
identifies its anycast ranges and CDN platform. The result identifies Framer rather than assuming
the target exposes its underlying CloudFront service. Fastly's
[X-Served-By documentation](https://www.fastly.com/documentation/reference/http/http-headers/X-Served-By/)
supports cache-chain interpretation; multiple CDN observations do not establish their order.
Header-name-only catalog candidates stay advisory. The Qantas deadline regression preserves typed,
completed DNS evidence through the signed worker, API and both persistence modes, while keeping
WAF null, protection inconclusive and all original operation/deadline bounds.

Regression tests replay the recorded headerless redirect through the scanner, signed worker,
projection and target-detail presenter. They assert Akamai/AS16625, separate CDN/WAF/cloud families,
one pinned GET, unchanged signed-operation bounds, no redirect expansion, zero enforcement claims,
safe historic presentation and dataset provenance. Generator tests reject remote failures and
exclude withdrawn prefixes. Existing corpus parity remains unchanged.

Release status and check results are recorded in PROGRESS.md under WAF-025. Deployment must contain
only this scoped fix: the working tree also contains unrelated direct-target and portal changes.
After deployment, run Detect WAF and CDN again through the normal owned-target UI. Do not rewrite
the old run or manufacture provider evidence in the database. The expected fresh observation is
Akamai CDN via ASN ownership with WAF effectiveness untested.
