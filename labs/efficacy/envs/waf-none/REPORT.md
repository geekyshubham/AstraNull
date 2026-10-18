# AstraNull Efficacy Lab Report: waf-none

## Summary

- **Lab ID**: waf-none
- **Compose Project**: anl-waf-none
- **Network**: anl-waf-none-net (subnet: 172.31.26.0/24, internal: true)
- **Target**: 172.31.26.10:80
- **Base Image**: nginx:1.27-alpine
- **Image ID**: `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
- **Probe/Test Image**: curlimages/curl:latest (`sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`)

## Configuration & Ground Truth

The service runs unadorned `nginx:1.27-alpine` configured to respond with HTTP 200 `origin-ok\n` to all requests. There is no WAF, ModSecurity, or filtering module present.

### Check Expectations

1. `waf.sqli_managed_marker.safe`: **gap**
   - No WAF or rule inspection present. Bounded inert SQLi marker (`astranull' OR '1'='0`) is allowed through to origin, returning 200 `origin-ok`.
2. `waf.xss_managed_marker.safe`: **gap**
   - No WAF present. Bounded inert XSS marker (`<astranull-xss-probe/>`) returns 200 `origin-ok`.
3. `waf.path_traversal_managed_marker.safe`: **gap**
   - No WAF present. Bounded inert path traversal marker (`../../astranull-probe`) returns 200 `origin-ok`.
4. `waf.fingerprint.safe`: **inconclusive_expected**
   - Check uses `waf_fingerprint_observation` probe kind. In `src/services/correlation.mjs`, observation-only probes unconditionally correlate to `verdict: 'inconclusive'`. The check logic notes: "No WAF was identified: one ordinary GET cannot establish WAF presence or blocking; run the WAF marker check to test enforcement." Therefore, "no WAF" is an inconclusive result rather than a conclusive protected or gap verdict.

## Proof after the address pool was freed

The dead fixture network `bgp-fixture-acceptance-20261014101054-60488_default` and its nine exited containers were removed with explicit approval. `up.sh` then created `anl-waf-none-net` and `anl-waf-none-target` became healthy.

From a throwaway container on that network:

- `GET http://172.31.26.10/` returned `200` and `origin-ok`
- the inert SQLi marker returned `200`
- the inert XSS marker returned `200` and `origin-ok`
- the inert path-traversal marker returned `200` and `origin-ok`

## Earlier blocker

During the first `up.sh`, Docker daemon refused creation of `anl-waf-none-net` with:
```
failed to create network anl-waf-none-net: Error response from daemon: invalid pool request: Pool overlaps with other one on this address space
```

### Cause
An old exited acceptance test network `bgp-fixture-acceptance-20261014101054-60488_default` (created 2026-10-14) is occupying `172.31.0.0/16`. All containers attached to it are stopped/exited.

### Safety Constraint
CONTRACT.md and safety guidelines strictly prohibit touching resources whose names begin with `bgp-*`:
> "Never stop, remove, or modify containers, networks, or volumes you did not create. Do not touch names starting with bgp- or astranull-postgres-local. Prefix every resource with anl-<lab-id>."

To unblock creation of `anl-waf-none-net` (and all other efficacy labs in `172.31.0.0/16`), the dead fixture network and its exited containers must be cleaned up by the user or explicitly authorized for removal:
```bash
docker rm bgp-fixture-acceptance-20261014101054-60488-route-cache-1 \
          bgp-fixture-acceptance-20261014101054-60488-bgp-engine-1 \
          bgp-fixture-acceptance-20261014101054-60488-collector-1 \
          bgp-fixture-acceptance-20261014101054-60488-pathstate-1 \
          bgp-fixture-acceptance-20261014101054-60488-ui-1 \
          bgp-fixture-acceptance-20261014101054-60488-connect-1 \
          bgp-fixture-acceptance-20261014101054-60488-kafka-1 \
          bgp-fixture-acceptance-20261014101054-60488-fixture-1 \
          bgp-fixture-acceptance-20261014101054-60488-opensearch-1
docker network rm bgp-fixture-acceptance-20261014101054-60488_default
```
