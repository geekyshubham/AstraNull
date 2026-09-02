# Agent and Probe Updates for WAF Posture

## Purpose

Extend AstraNull probes and customer agents so WAF posture can be validated safely from outside and inside.

## Probe worker additions

| Capability | Description |
|---|---|
| WAF fingerprint probe | Runs a bounded, pre-reserved, destination-pinned HTTP plan; signed jobs do not follow redirects or run standalone DNS/TLS hint collectors. |
| WAF marker probe | Sends customer-approved marker request with nonce. |
| Block-page fingerprinting | Hashes safe block/challenge response metadata. |
| Protected/direct path comparison | Compares WAF path vs direct origin path where approved. |
| Low-rate limit probe | Sends bounded low count to test endpoint and stops on expected control. |
| Connector-independent schedule | Can run without customer credentials. |

## Agent additions

| Capability | Description |
|---|---|
| WAF canary observer | Detects whether a marker nonce reaches origin/canary zone. |
| Route label | Reports where observation happened: edge, app, origin, internal segment, canary. |
| WAF log pointer | Optional metadata pointer to customer log entry, not full logs. |
| Placement confidence | Tells whether agent is correctly placed for WAF verdict. |
| Observation dedupe | Exact-once nonce/job observation. |

## New agent capability flags

| Flag | Meaning |
|---|---|
| `waf_canary_observer` | Can observe WAF marker/canary requests. |
| `http_access_log_metadata` | Can report redacted log metadata. |
| `origin_path_observer` | Can distinguish direct-origin vs protected path labels. |
| `waf_validation_ready` | Agent placement/canary setup is sufficient for strong WAF verdicts. |
| `connector_log_pointer` | Can attach external log reference ids. |

## Probe profile examples

### Fingerprint

```json
{
  "kind": "outside_in_waf_scan",
  "max_requests": 13,
  "timeout_ms": 5000,
  "follow_redirects": false,
  "collect": [
    "status_code",
    "waf_product_hint",
    "marker_probes",
    "posture_status",
    "posture_label"
  ]
}
```

The signed worker hard-forces `followRedirects=false` and `collectNetworkHints=false` at execution.
A/AAAA destination vetting is separately reserved and attested; it is not fingerprint evidence.

### Marker

```json
{
  "kind": "waf_marker",
  "max_requests": 1,
  "timeout_ms": 5000,
  "marker_type": "header",
  "marker_name": "X-AstraNull-WAF-Canary",
  "nonce_hash_only": true,
  "expected_action": "block"
}
```

## Observation shape

```json
{
  "agent_job_id": "uuid",
  "test_run_id": "uuid",
  "target_id": "uuid",
  "nonce_hash": "sha256:...",
  "metadata": {
    "observation_type": "waf_marker_seen",
    "route_label": "origin_canary",
    "observed_at": "2026-07-02T00:00:00Z",
    "placement_confidence": 0.94
  }
}
```

## Safety enforcement

Probe worker must reject jobs when:

- signature invalid,
- requested max requests exceeds catalog,
- timeout exceeds catalog,
- raw payload field exists,
- target id is not approved,
- tenant kill switch active,
- safe window closed,
- check requires agent but no ready agent/canary exists.

Agent must reject/report invalid observations when:

- job not acked,
- nonce missing,
- target mismatch,
- raw packet/body/header/log field exists,
- observation exceeds run event cap.

## Placement confidence

| Signal | Meaning |
|---|---|
| Agent observes protected-path baseline | Agent can see relevant app path. |
| Agent does not observe blocked marker | Supports before-origin blocking. |
| Agent observes direct-origin marker | Confirms bypass. |
| Agent never observes any baseline | Placement incomplete. |
| Multiple agents conflict | Mark inconclusive and show placement issue. |

## Done criteria

- Probe job signing includes WAF profile fields.
- Probe worker stores metadata-only results.
- Agent reports WAF marker observations with nonce hash only.
- Correlation can distinguish blocked-before-origin vs reached-origin.
- Safety unit tests cover forbidden raw fields and max request enforcement.
