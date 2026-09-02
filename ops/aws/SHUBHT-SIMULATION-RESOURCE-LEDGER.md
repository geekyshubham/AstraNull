# shubht.online bounded simulation resource ledger

- Status: **live simulation target**
- Created: 2026-09-02
- Review/teardown by: **2026-09-09**
- AWS account: `423370095676`
- Region/profile: `us-east-1` / `astranull-staging`

## Safety boundary

This host is an isolated destination for AstraNull's bounded safe probes. It is not a traffic generator and does not contain attack tooling. The nginx target limits clients to 5 requests/second with a burst of 10 and responds with HTTP 429 above that limit. High-scale traffic remains unauthorized and must use AstraNull's SOC-governed adapter workflow.

Do not run unmanaged DDoS, amplification, volumetric, or high-concurrency traffic against this host. The only executed guardrail exercise was 20 requests with concurrency 10; it returned 15 HTTP 200 and 5 HTTP 429 responses.

## AWS resources

All resources have `Project=AstraNull`, `Environment=simulation`, `Domain=shubht.online`, and `DeleteAfter=2026-09-09` tags. The date tag is advisory; no automatic deletion policy is attached.

| Resource | Identifier / configuration |
|---|---|
| EC2 instance | `i-03fb4459561330c5a`, `shubht-simulation-target`, `t3.micro` |
| AMI | Canonical Ubuntu 24.04 amd64 `ami-0d7f022123f8ff19d` |
| VPC / subnet | `vpc-0be130ea1ba98f8ab` / `subnet-06d79ba26c0527ded` |
| Private address | `172.31.25.52` |
| Elastic IP | `52.203.98.1`, allocation `eipalloc-0415910d72985c18a`, association `eipassoc-069f82ac919e9db62` |
| ENI | `eni-0f64d3bd5f52a5650` (instance-managed) |
| Security group | `sg-0153c5d7e12f3b331`, `shubht-simulation-target` |
| Key pair | `shubht-simulation-target`, `key-047ab0fe42255aaf3` |
| Local private key | `ops/aws/.shubht-simulation-key.pem`, mode 600, ignored by `*.pem` |
| Root volume | `vol-04636347ef7c1c037`, encrypted 10 GiB gp3, `DeleteOnTermination=true` |
| Instance metadata | IMDSv2 required; hop limit 1; IPv6 and metadata tags disabled |

Security-group ingress is exactly:

- TCP 80 from `0.0.0.0/0` for HTTP redirect and ACME.
- TCP 443 from `0.0.0.0/0` for bounded probes.
- TCP 22 from operator address `123.252.204.182/32` only.

No application, database, agent-management, or traffic-generation port is exposed. Default outbound access remains enabled for package updates and ACME renewal.

## Service and TLS

- nginx 1.24, enabled and active.
- `GET /health` returns `status=ok`, service `astranull-bounded-simulation-target`, and `traffic_generation=false`.
- `GET /.well-known/astranull-simulation` declares `bounded-safe-probes-only`, `5r/s`, burst 10, and `high_scale=false`.
- HTTP redirects to HTTPS.
- Let's Encrypt certificate covers `shubht.online` and `www.shubht.online`; valid 2026-09-02 through 2026-12-01.
- Certbot renewal timer is installed.

Operator access:

```bash
ssh -i ops/aws/.shubht-simulation-key.pem \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/tmp/shubht-kh \
  ubuntu@52.203.98.1
```

If the operator address changes, first authorize only the replacement `/32`, verify SSH, then revoke the stale rule. Do not open SSH to the internet.

## Namecheap DNS

Pre-mutation backup: [`dns-backup/shubht.online-prelab-20260902T171930Z.txt`](dns-backup/shubht.online-prelab-20260902T171930Z.txt).

Namecheap BasicDNS remains authoritative. The two parking records were replaced; Zoho email records were preserved.

| ID | Type | Host | Value | TTL |
|---|---|---|---|---|
| `532964172` | A | `@` | `52.203.98.1` | 300 |
| `532964189` | A | `www` | `52.203.98.1` | 300 |
| `532965351` | TXT | `_astranull-challenge` | AstraNull ownership proof | 300 |
| `525824481` | MX 10 | `@` | `mx.zoho.in.` | preserved |
| `525824587` | MX 20 | `@` | `mx2.zoho.in.` | preserved |
| `525824590` | MX 50 | `@` | `mx3.zoho.in.` | preserved |
| `525822988` | TXT | `@` | Zoho SPF | preserved |
| `525824835` | TXT | `zmail._domainkey` | Zoho DKIM public key | preserved |

Both authoritative Namecheap servers and public resolvers `1.1.1.1`, `8.8.8.8`, and `9.9.9.9` returned `52.203.98.1` for apex and `www` after cutover. Zoho MX/SPF/DKIM remained present.

## AstraNull onboarding and bounded validation

Live control plane: `https://astranull.site`

| Object | Identifier / result |
|---|---|
| Tenant / environment | `ten_demo` / `env_demo` |
| Target group | `tg_e667ec494cba38ec`, `shubht.online bounded simulation`, `external_only` |
| Target | `tgt_be430ffbeba98c0b`, FQDN `shubht.online` |
| Ownership challenge | `dns_734424bd96938cff`, resolved |
| Verification | `dns_verified`, source `dns_txt` |
| Eligibility | `eligible` |
| Safe run | `run_c66c020c3cb1ce11`, check `origin.leak_scan.safe`, status `verdicted` |
| Evidence event | `evt_a9ebfd4407cf155f`, `probe_result` / `signed_probe` / `probe_worker` |
| Verdict | `edge_protected`, confidence `external_only` |

The signed worker recorded 15 probe requests and two destination-resolver operations in 190 ms. The run's safety constraints were 15 events, 120 seconds maximum duration, one concurrent run per target group, and 60 runs/hour. Placement was deliberately refused as `missing_agent` / `unbound`: no internal path proof was claimed without an optional agent.

### Complete 721-vector evaluation (2026-09-02)

The canonical catalog was evaluated row-by-row against this exact target profile (`fqdn`, `external_only`, no agent). Complete custody evidence is committed at [`evidence/shubht-online-full-catalog-evaluation-2026-09-02.json`](evidence/shubht-online-full-catalog-evaluation-2026-09-02.json).

| Disposition | Catalog rows | Meaning |
|---|---:|---|
| Evaluated with bounded evidence | 404 | At least one directly linked, target-compatible customer-safe check ran and is referenced by exact run/event IDs. |
| Additional input required | 10 | A bounded check exists but requires a customer-declared URL/path or equivalent setup not fabricated for this target. |
| SOC-gated, not executed | 258 | Requires governed authorization/adapters; no unmanaged high-scale traffic was generated. |
| Monitor-only, not executed | 49 | Passive/integration evidence or a non-routable outside-in scope boundary; no active probe is claimed. |

The 404 evaluated rows map to 194 unique directly linked safe checks. All 194 ran sequentially to terminal `verdicted` state with zero refusals and exactly one `probe_result` event each. All events have producer `signed_probe`, source `probe_worker`, and confidence `external_only`. Aggregate check verdicts were 31 `edge_protected`, 26 `edge_exposed`, and 137 `inconclusive`; the signed worker recorded 509 bounded requests/operations. Verdicts remain check-level evidence—the artifact does not synthesize a per-vector outcome where checks are shared.

The target group's `max_runs_per_hour` was temporarily raised from 60 to 240 only to admit the complete sequential bounded inventory. Per-check request/duration caps, the one-active-run constraint, external-only mode, and the host's 5 requests/second burst-10 limiter remained enforced. The group policy was restored to 60 runs/hour and zero minimum interval after completion. No agent, SOC adapter, or high-scale executor ran.

One `waf.fingerprint.safe` attempt (`run_98a2dac76251a932`) exposed a release packaging defect: the old worker image omitted `db/seeds/waf-product-catalog.json`, logged `ENOENT`, restarted, and left the run without evidence. The expired run was cancelled. The catalog asset and a release-archive regression were added in commit `3aeb9c0f`; exact image `sha256:b8d5c9842aa584f68b635e62be5e462b73fec2f86acc3f47294cf9aaa5a2b27c` was deployed after an encrypted database backup. Retry `run_caf69ab12a3c69c8` verdicted successfully, the worker remained healthy, and no further missing-catalog error occurred.

Custody binds 721 unique rows, 194 unique selected runs/events, exact tenant/group/target/check identifiers, generator SHA-256, generated-catalog/matrix/live-input SHA-256 values, and a `json-key-sorted-v1` content digest. Independent regeneration was byte-identical and gitleaks reported zero findings.

Do not repeatedly execute the run set as a load test. Additional customer-safe checks must stay within the product's bounded policies; high-scale tests require SOC authorization.

## Cost controls

Billable items are the `t3.micro`, 10 GiB gp3 volume, Elastic IP/public IPv4, and ordinary data transfer. Stopping the instance does **not** remove volume or public IPv4 charges. The intended control is teardown by 2026-09-09, reinforced by the `DeleteAfter` tags and the copy-paste procedure below. Verify current AWS pricing in Billing/Cost Explorer; this ledger does not hard-code a price estimate.

Useful inventory check:

```bash
aws ec2 describe-instances --profile astranull-staging --region us-east-1 \
  --filters 'Name=tag:Domain,Values=shubht.online' \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,Type:InstanceType,IP:PublicIpAddress,Tags:Tags}'
```

## Rollback and teardown

**DNS must be moved away from `52.203.98.1` before releasing the address.** Releasing first can send visitors and AstraNull probes to a future AWS customer who receives the recycled IP.

### 1. Remove AstraNull ownership and restore Namecheap parking

The pre-lab state was an apex URL redirect to `http://www.shubht.online/` plus a `www` CNAME to `parkingpage.namecheap.com.`. Restore it with:

```bash
namecheap dns rm shubht.online 532964172 --force
namecheap dns rm shubht.online 532964189 --force
namecheap dns rm shubht.online 532965351 --force
namecheap dns add shubht.online --type URL --name @ \
  --value 'http://www.shubht.online/' --ttl 1800
namecheap dns add shubht.online --type CNAME --name www \
  --value 'parkingpage.namecheap.com.' --ttl 1800
namecheap dns list shubht.online
```

Do not delete the Zoho MX, SPF, or DKIM rows. Wait until authoritative and public DNS no longer returns `52.203.98.1`:

```bash
for r in dns1.registrar-servers.com dns2.registrar-servers.com 1.1.1.1 8.8.8.8; do
  echo "$r: $(dig +short @$r A shubht.online | tr '\n' ' ')"
done
```

Then archive/delete the live AstraNull objects using a fresh admin bearer token:

```bash
B=https://astranull.site
A='authorization: Bearer <fresh-admin-token>'
curl -f -X DELETE "$B/v1/target-groups/tg_e667ec494cba38ec/targets/tgt_be430ffbeba98c0b" -H "$A"
curl -f -X DELETE "$B/v1/target-groups/tg_e667ec494cba38ec" -H "$A"
```

### 2. Delete AWS resources

After DNS is confirmed moved away:

```bash
aws ec2 terminate-instances --profile astranull-staging --region us-east-1 \
  --instance-ids i-03fb4459561330c5a
aws ec2 wait instance-terminated --profile astranull-staging --region us-east-1 \
  --instance-ids i-03fb4459561330c5a

# Termination deletes vol-04636347ef7c1c037 and the instance ENI.
aws ec2 release-address --profile astranull-staging --region us-east-1 \
  --allocation-id eipalloc-0415910d72985c18a
aws ec2 delete-security-group --profile astranull-staging --region us-east-1 \
  --group-id sg-0153c5d7e12f3b331
aws ec2 delete-key-pair --profile astranull-staging --region us-east-1 \
  --key-name shubht-simulation-target
rm -f ops/aws/.shubht-simulation-key.pem /tmp/shubht-kh
```

If releasing the address reports that it is still associated, run this once and retry:

```bash
aws ec2 disassociate-address --profile astranull-staging --region us-east-1 \
  --association-id eipassoc-069f82ac919e9db62
```

### 3. Verify deletion

```bash
aws ec2 describe-instances --profile astranull-staging --region us-east-1 \
  --instance-ids i-03fb4459561330c5a \
  --query 'Reservations[].Instances[].State.Name'
aws ec2 describe-addresses --profile astranull-staging --region us-east-1 \
  --allocation-ids eipalloc-0415910d72985c18a
aws ec2 describe-security-groups --profile astranull-staging --region us-east-1 \
  --group-ids sg-0153c5d7e12f3b331
```

The final two commands should return `InvalidAllocationID.NotFound` and `InvalidGroup.NotFound`; the terminated instance remains visible in EC2 history temporarily.

## Credential rotation

The AWS access key used for this deployment was pasted into chat. Its identifier ends in `S36WV`; the secret is not recorded here. Disable/delete that key and replace it after this work. The earlier key ending in `JJFNH` already failed AWS authentication and should also be removed if still listed. Namecheap credentials previously disclosed through operator channels and the demo administrator password disclosed in chat should likewise be rotated. No AWS secret, Namecheap API key, bearer token, password, or private key is committed in this repository.
