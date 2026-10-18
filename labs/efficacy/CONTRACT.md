# AstraNull efficacy lab — shared worker contract

Every worker agent MUST read this file first and follow it exactly.

## Goal

Stand up real, deliberately vulnerable or deliberately mis-protected environments in local Docker,
run AstraNull's real catalog checks against them, and measure whether AstraNull detects the
protection gaps we planted (true/false positives and negatives). Ground truth comes from how each
lab is configured, never from AstraNull's own output.

## Hard safety rules

1. Probe/check traffic may only target containers on lab networks in `172.31.0.0/16` that this
   lab created. Never send check traffic to the public internet or to any host outside the lab.
   Internet access is allowed only for `docker pull`, image builds (apt/apk/npm) and reading docs.
2. Lab networks are `internal: true` (no egress) unless an image build step needs a separate build network.
3. Do not add attack or flood tooling (no sqlmap, nikto, hping floods, amplification scripts, load generators).
   Vulnerable apps are only targets; the only traffic generator is AstraNull's own bounded catalog probes.
4. Never push images, never `docker login`, never publish ports except to `127.0.0.1` when unavoidable.
5. Never stop, remove or modify containers, networks or volumes you did not create. Existing
   `bgp-*` and `astranull-postgres-local` containers must not be touched. Prefix everything you create
   with your compose project name `anl-<lab-id>`.
6. Repository source is READ-ONLY for workers: do not edit anything under `src/`, `workers/`, `tests/`,
   `scripts/`, `db/`, `docs/`, `apps/`, `ops/`, `PROGRESS.md`, `package*.json`. Write only inside your own
   directory `labs/efficacy/<area>/<lab-id>/` and `/tmp/astranull-lab/<lab-id>/`. If you believe product
   code has a defect, describe it with file:line and a reproduction in your REPORT.md — do not fix it.
7. No git commands that change state (no commit, checkout, stash, reset, clean, branch, push).
8. Never print, copy or store secrets, tokens, private keys or account emails. Use synthetic data only.
9. Cap every container: `cpus` <= 1.0 and `mem_limit` <= 768m unless your brief says otherwise.

## Network and naming allocation

| Lab id | Subnet | Compose project |
|---|---|---|
| harness | 172.31.10.0/24 | anl-harness |
| fault-lab | (network none) | anl-fault-lab |
| waf-crs-block | 172.31.21.0/24 | anl-waf-crs-block |
| waf-crs-detect | 172.31.22.0/24 | anl-waf-crs-detect |
| waf-crs-sqli-gap | 172.31.23.0/24 | anl-waf-crs-sqli-gap |
| waf-crs-pl4 | 172.31.24.0/24 | anl-waf-crs-pl4 |
| waf-coraza | 172.31.25.0/24 | anl-waf-coraza |
| waf-none | 172.31.26.0/24 | anl-waf-none |
| nfw-router | 172.31.31.0/24 (client) + 172.31.32.0/24 (server) | anl-nfw-router |
| nfw-ipv6-gap | 172.31.33.0/24 + fd00:a57a:33::/64 | anl-nfw-ipv6-gap |
| dns-lab | 172.31.41.0/24 | anl-dns-lab |
| reflector-lab | 172.31.42.0/24 | anl-reflector-lab |
| tls-proto-lab | 172.31.51.0/24 | anl-tls-proto-lab |
| ratelimit-lab | 172.31.52.0/24 | anl-ratelimit-lab |
| l7-surface-lab | 172.31.53.0/24 | anl-l7-surface-lab |

Name docker networks exactly `anl-<lab-id>-net` (for nfw-router: `anl-nfw-router-client` and
`anl-nfw-router-server`) with `name:` set explicitly in compose so the harness can attach to them as
`external` networks. Use static `ipv4_address` for every target.

## Required outputs for every environment lab

Inside `labs/efficacy/envs/<lab-id>/`:

- `docker-compose.yml`, plus any Dockerfiles/configs.
- `up.sh` (idempotent, waits for health) and `down.sh` (removes only this project's resources).
- `manifest.json` following the schema below. It is the ground truth the runners grade against.
- `STATUS.md` (append progress as you go) and `REPORT.md` (final: what runs, health evidence,
  limitations, any image digests used — record `docker image inspect --format '{{.Id}}'` for each image).

Leave the lab RUNNING when you finish (runners need it). `down.sh` is for later cleanup.

### manifest.json schema

```json
{
  "schema": "astranull.efficacy-lab.v1",
  "lab_id": "waf-crs-detect",
  "networks": ["anl-waf-crs-detect-net"],
  "targets": [
    {
      "name": "dvwa-behind-crs-detection-only",
      "address": "172.31.22.10",
      "hostname": null,
      "ports": [{ "port": 80, "protocol": "tcp", "service": "http" }],
      "planted_condition": "ModSecurity CRS 4 in DetectionOnly: WAF present, nothing blocked",
      "declarations": { "waf_block_signature": { "status": 403, "body_contains": "..." } },
      "expectations": [
        { "check": "waf.sqli_managed_marker.safe", "expected": "gap", "why": "DetectionOnly never blocks" },
        { "check_prefix": "waf.evasion_", "expected": "gap", "why": "base marker not blocked" }
      ]
    }
  ],
  "verification": ["curl from a container on the lab net shows the marker request returns 200"]
}
```

`expected` vocabulary (grading is on the security conclusion, not exact field names):
`protected` (control enforced, no gap), `gap` (control missing / not enforced / exposed),
`not_applicable` (check needs something this lab cannot provide), `inconclusive_expected`
(the check is designed to withhold a verdict here). Prove each planted condition independently
(e.g. curl/nc/dig from a throwaway container on the same lab network) and put that proof in REPORT.md.

## Harness interface (built by the `harness` worker)

`labs/efficacy/harness/run-checks.sh --manifest <path> [--checks id1,id2|--prefix waf.] --out <dir>`
runs the requested AstraNull catalog checks through the real control plane + signed probe worker
against the manifest targets, then writes `<out>/results.jsonl` (one row per check x target with the
AstraNull verdict, outcome, evidence summary and the manifest expectation) and `<out>/summary.md`
(confusion matrix: detected gap / missed gap / false alarm / correct protected / inconclusive).
Until it exists, runner workers wait by polling `labs/efficacy/harness/READY` (do not build your own).

## Done means

Your final message must be <= 25 lines: what you built, where, what you proved, what failed, and
any suspected AstraNull detection defect with evidence paths. No secrets.
