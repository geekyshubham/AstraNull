# ADR-0035: VirusTotal UI source for passive subdomain import

Status: Accepted, 2026-10-17. Amends [ADR-0031](0031-keyless-certificate-transparency-subdomain-source.md).

## Decision

Confirmed subdomain imports can use `ASTRANULL_SUBDOMAIN_SOURCE=virustotal_ui`, following the
operator-supplied script: `/ui/domains/{domain}/subdomains`, 40 records per page,
`relationships=resolutions`, base64 JSON `{limit, offset}` cursors, fresh UI request headers,
Chrome impersonation through `curl_cffi`, and up to eight parallel page requests. No VirusTotal
API key is needed. A blank source selects UI, even when an official API key is present.
Explicit `crtsh`, `virustotal` and `disabled` retain their existing meanings.

The Python helper has the operator-requested default rotating proxy endpoint and credential.
`ASTRANULL_SUBDOMAIN_PROXY_URL` overrides it server-side. Each request opens its own connection
through that endpoint; actual exit-IP rotation is controlled by the proxy provider. The helper
does not verify or promise a distinct exit IP for every request. Credentials travel over stdin
between Node and Python, never command-line arguments, responses, audits or error messages.

The control-plane images install the pinned `scripts/requirements-subdomains.txt` into a venv
at build time. Runtime never downloads packages. `ASTRANULL_SUBDOMAIN_PYTHON` selects the interpreter
(images set their venv path). Without an override the helper uses the repo-local
`.data/subdomains-venv/bin/python` if installed, otherwise `python3`. For local development:

```sh
python3 -m venv .data/subdomains-venv
.data/subdomains-venv/bin/pip install -r scripts/requirements-subdomains.txt
npm run dev:api
```

Control-plane images remove the venv and system pip installers after installing curl-cffi.
This removes their vulnerable vendored packaging dependencies without changing the runtime transport.

## Bounds and errors

Amended 2026-10-18: the default UI source follows the supplied script's full-fetch behavior.
It fetches every offset page through the finite `meta.count`, with no 200/1,000-result cap and
no 45-second overall deadline. The old `ASTRANULL_SUBDOMAIN_MAX_RESULTS` setting applies only to
the optional official API / Certificate Transparency sources; even existing deployments set to
200 read all UI-source pages. Only eight requests/futures are in flight at a time, rather than
allocating a future for every page. The standalone helper retains the supplied script's defaults. The web adapter uses 10-second
per-request timeouts, three attempts and backoff starting at one second, with a final sequential
recovery pass for transient failures. A CAPTCHA-required response stops immediately; authentication
failures on later pages stop scheduling more pages and preserve collected results as incomplete. Responses remain capped at 2 MiB per page; redirects are never followed.

The Node transport streams the helper output without the former 47-second process kill or
2 MiB aggregate output limit. Imported inventory reads all keyset pages instead of stopping
at 2,000 rows; a repeated cursor fails explicitly rather than returning an incomplete list as
complete. Parent normalization, strict-descendant validation, authorization and auditing remain
unchanged. First-page errors add no hosts; unrecoverable later pages preserve successful results
with `truncated: true` and a typed `stop_reason`. A full first page without a reported count is
marked `unknown_total`, and unexpected short pages are marked `incomplete_source`.
The portal keeps these operational details internal: customers see neutral import outcomes,
and an incomplete discovery is stated without exposing proxy, quota, credential or retry details.

## Consequences

This endpoint is undocumented and may change independently of the official API. An import
failure remains visible; no fallback silently changes its provenance. Operators can select
Certificate Transparency or the official API explicitly. Only normalized hostnames and source
metadata persist, using existing target creation and `target.subdomains_enumerated` auditing;
no migration or event schema change is needed. Confirmation, permissions, ownership inheritance,
tenant isolation and the existing initial-detection gates remain in force. Passive enumeration
does not send requests to candidate hosts or establish protection readiness.

## Repair validation (2026-10-18)

The AWS image builds successfully. A live HTTP import/list check inside that image, compared
with an independent run of the supplied script for `iana.org`, read all 54 source records
across two pages and imported/displayed all 53 valid strict descendants (the apex is excluded).
The sets matched exactly and `truncated` was false. Automated API coverage also imports and
lists 2,401 hosts, proving both former caps are gone; Python coverage checks full pagination,
parallelism, sequential page recovery, and requests continuing beyond 45 seconds.


## Discovery progress and cancellation (2026-10-18)

The portal opts into `Accept: text/event-stream` on the existing reviewed POST. It closes the
confirmation dialog immediately and shows source-record / declaration counts with Stop discovery.
The response sends `data: {"type":"progress","progress":{...}}` frames, followed by exactly one
`result` or `error` frame with `payload` while the client stays connected. Permission/body failures before streaming retain ordinary
HTTP JSON errors; source/target errors after headers carry their status in the error payload.
Legacy JSON callers retain the existing response contract.
The SSE content type follows [Caddy's immediate-flush behavior](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming)
so progress can reach the browser as it is written.

Disconnect, Stop discovery and route unmount abort the helper and stop subsequent declarations.
Already committed hosts remain, with a cancelled partial enumeration audit; there is no rollback
of child targets or their independently queued initial observations. Source/helper and client
stream inactivity have 45-second watchdogs, refreshed by real progress. These are idle limits,
not a total runtime or page-count cap. A connection that stalls during declaration reports that
already declared hosts remain available. The portal no longer claims a bounded result list or
completion within a minute, and operational source/proxy details remain internal.

Regression coverage checks terminal CAPTCHA rejection, child-process termination, stalled helper
and stream handling, immediate progress before source completion, cancellation during declaration,
and desktop/mobile import. A live request for the reported domain now ends promptly with the
source rejection instead of waiting through minutes of retries; successful inventory cannot be
claimed while the upstream requires human validation.
