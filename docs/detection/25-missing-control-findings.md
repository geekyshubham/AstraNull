# Missing-control findings

Decision record: [ADR-0034](../adr/0034-missing-control-findings-efficacy-and-remediation-assistant.md).

## Contract

Every catalog check has exactly one entry in `src/contracts/missingControls/` (`waf.mjs`, `application.mjs`, `network.mjs`, owned by `vector_family`):

| Field | Meaning |
|---|---|
| `control_family` | One of the 23 families in `families.mjs` (network firewall ingress, WAF managed rules, rate limiting, DNS zone-transfer restriction, …), each mapped to a layer: `network`, `edge_waf`, `edge_cdn`, `dns`, `origin` or `operations`. |
| `missing_control` | What the customer's environment lacks when the check flags a gap. |
| `required_policy` | The policy or configuration they need. |

`tests/unit/missing-controls-catalog.test.mjs` fails on a missing or extra check, an unknown family, generic or placeholder text, or an entry in the wrong group file.

## Provider guidance

`src/contracts/providerRemediation.mjs` gives, for every family and provider (`gcp`, `aws`, `azure`, `cloudflare`, `akamai`, `fastly`, `generic`), the provider control, 2–5 steps and official documentation. Where a provider has no native control for a family the entry says so and places the control in the right layer instead of inventing a product.

`src/lib/missingControlProjection.mjs` orders guidance by the target's detected providers on the layer that owns the control (cloud for network and origin families; WAF then CDN for edge-WAF families; CDN then WAF for edge-CDN families; none for DNS and operations), then vendor-neutral steps; the remaining providers are listed separately. Unknown detected vendors are reported rather than mapped. The projection keeps `attribution: 'unattributed'`: it is advice for the detected provider, not proof of which control failed.

## Evidence wording

Verdict explanations name the observed gap: the managed-rule attack class that reached the origin, every declared-deny port that answered (most sensitive first), the nameservers that allowed AXFR, and the evasion transform that passed while the plain marker was blocked.

## Gaps inferred without a declaration

See ADR-0034 decision 3 for the nine checks that become gap-capable from external evidence alone, their guards (attested I/O, non-CDN peer, agreeing samples, not an accept-all host) and the upgrades that remain open because the producer does not yet collect the deciding fact. `tests/unit/inferred-missing-control.test.mjs` exercises control-missing, control-present and guard cases for each.
