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

## Bounds and errors

Existing limits remain: default 200 imported results, ceiling 1,000, 45-second source deadline,
15-second request timeout, and no more than `ceil(maxResults / 40)` pages. Responses are capped
at 2 MiB per page. Network failures, 403, 429 and server failures receive at most five attempts
with exponential backoff starting at 15 seconds, only while the deadline permits. Other failures
stop immediately. Redirects are never followed. The parent comes from the declared target,
and only normalized strict descendants can become declarations.

First-page failure adds no hosts and returns the existing typed source errors. Later page
failures retain successful pages and report `truncated: true` with `stop_reason`, including
`rate_limited`, `auth_failed`, `unreachable`, `failed`, or `response_too_large`. Unknown totals on
a full first page report `unknown_total`; an unexpectedly short page reports `incomplete_source`.
Result/page caps report `max_results`. Node kills a stuck helper after 47 seconds.
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
