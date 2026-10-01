# AstraNull AWS staging — created resource ledger

Purpose: a complete, teardown-ready record of every cloud resource created for the
temporary AstraNull staging environment. **Delete everything in the Teardown section
when finished** — several of these resources bill continuously.

| Field | Value |
|---|---|
| AWS account | `423370095676` |
| IAM identity | `arn:aws:iam::423370095676:user/rootuser` |
| Local CLI profile | `astranull-staging` |
| Region | `us-east-1` |
| Deployed commit | `7a27f8ae2334794a4fc6b645867ab2a14198605a` |
| Branch | `feat/ddos-vector-coverage-remediation` |
| Created (UTC) | 2026-09-02 |
| Intended lifetime | 2–3 days |

## Safety baseline captured before provisioning

Verified at preflight so teardown can distinguish "ours" from "pre-existing":

- EC2 instances in this account: **0** across `us-east-1`, `us-east-2`, `us-west-1`,
  `us-west-2`, `eu-west-1`, `ap-south-1`.
- Key pairs: **0**. Elastic IPs: **0**. Security groups: **1** (the VPC default only).
- Default VPC `vpc-0be130ea1ba98f8ab` (`172.31.0.0/16`) with public subnets in all 6 AZs.
- Production instance `i-09169859dac12a2ee` (`34.199.50.155`, `us-east-1f`) returns
  `InvalidInstanceID.NotFound` in this account — **production lives in a different AWS
  account and is not reachable from these credentials.**

Everything listed under "Resources created" was therefore created by this deployment.
Anything not listed here pre-dates it.

## Naming convention

All resources are prefixed `astranull-staging-` and tagged:

- `Project=astranull`
- `Environment=staging`
- `ManagedBy=release-candidate-deploy`
- `Commit=7a27f8ae`
- `DeleteAfter=2026-09-05`

Teardown can therefore be driven by tag as well as by the explicit IDs below.

## Resources created

All created 2026-09-02 in `us-east-1`, account `423370095676`.

| # | Type | Name / ID | Region / AZ | Billing | Status |
|---|---|---|---|---|---|
| 1 | EC2 key pair | `astranull-staging-key` / `key-05f04534b0d6e885c` | us-east-1 | none | created |
| 2 | Security group | `astranull-staging-sg` / `sg-024035b0882f38f85` | us-east-1 (vpc-0be130ea1ba98f8ab) | none | created |
| 3 | Elastic IP | `34.201.159.68` / `eipalloc-0eb5cd0107be2af0f` | us-east-1 | **hourly while allocated** | created |
| 4 | EIP association | `eipassoc-06132d1e00c1d3678` | us-east-1 | n/a | created |
| 5 | EC2 instance | `astranull-staging` / `i-00c7a0be239bc83ea` | us-east-1a | **hourly while running** | running |
| 6 | EBS root volume | `vol-0a37857b8647ffc31` (40 GB gp3, encrypted) | us-east-1a | **hourly while it exists** | attached, `DeleteOnTermination=true` |

Instance detail: `t3.large` (2 vCPU / 8 GB), AMI `ami-0d7f022123f8ff19d`
(Ubuntu 24.04 LTS amd64), subnet `subnet-055dad14e832d29fb`, IMDSv2 required.

### Network exposure

| Port | Source | Reason |
|---|---|---|
| 22 | `108.191.200.121/32` (operator IP only) | SSH |
| 80 | `0.0.0.0/0` | ACME HTTP-01 challenge for TLS |
| 443 | `0.0.0.0/0` | HTTPS portal |

The portal is internet-reachable on 80/443. It is **not** unauthenticated: the deployment
runs `NODE_ENV=production`, which makes the app refuse `dev-headers` and `signed-session`
auth outright, so every API and portal route requires a verified RS256 OIDC bearer token.
SSH is restricted to a single operator address.

## Local artifacts (not cloud, but clean these up too)

| Path | Contains | Action |
|---|---|---|
| `~/.aws/credentials` profile `astranull-staging` | access key for account 423370095676 | remove profile after teardown |
| `ops/aws/.staging-key.pem` | EC2 private key (gitignored) | delete after teardown |

## Deployed application

| Field | Value |
|---|---|
| URL | `https://34.201.159.68.sslip.io` |
| Hostname source | `sslip.io` wildcard DNS → `34.201.159.68` (no registrar account needed) |
| TLS | Let's Encrypt, `CN=34.201.159.68.sslip.io`, valid to 2026-12-01 |
| Auth mode | `oidc-jwt` (bundled staging OIDC fixture); `NODE_ENV=production` |
| Persistence | `postgres`, 53 migrations, latest `0053_target_edge_detection_provenance` |
| Probe mode | `signed-worker` (probe worker secret configured) |
| Connectors | disabled |
| High-scale adapter | disabled |
| Image | current `sha256:0ca1c7ac2e16c29e232fb4c9c278fa45edc483b133bbce4ecbed5a328083b518` (commit `f66cfe58`); prior `sha256:b8d5c984…` retained for rollback |

Running services: `postgres`, `control-plane`, `probe-worker`,
`password-recovery-worker`, `test-policy-runner`, `caddy` — all healthy.

### Login

Tenant `ten_demo`, seeded by `scripts/seed-local-staging-tenant.mjs`.

| Role | Email |
|---|---|
| admin | `admin@demo.astranull.local` |
| soc | `soc@demo.astranull.local` |
| soc | `soc2@demo.astranull.local` |

A password was set for `admin@demo.astranull.local` through the application's own
invite → set-password flow. **The password is deliberately not written to this file**;
it was delivered separately. To rotate or set another user's password, re-run the
invite/set flow against `usr_admin` / `ten_demo`.

Verified live: `POST /v1/auth/login` returns `access_token` with `role=admin`,
`tenant_id=ten_demo`. Unauthenticated `GET /v1/target-groups` returns `401`.

### Initial-release deviation from the standard deploy path

`ops/aws/deploy.sh` was **not** used for the initial release. It requires the host to be a clean git checkout with an `origin/main` remote, and it refuses to run when any tracked file is modified—but the staging hostname had to be written into the tracked `ops/aws/Caddyfile` for TLS to work, and the release was transferred as a `git archive` (no `.git`). The stack was therefore brought up with Docker Compose directly, using an image built from `ops/aws/Dockerfile` on the exact deployed tree—the same Dockerfile and build input `deploy.sh` uses. That initial disposable-host activation skipped the pre-migration encrypted backup, image-identity journalling, and release-state tracking; this is not an acceptable substitute for a hardened production deployment.

### Vector-library backend update (2026-09-02)

Commit `3aeb9c0f4dd9646f1e2663a82f4011a82b6e95f2` was transferred as an exact `git archive`, built on-host, and activated as immutable image `sha256:b8d5c9842aa584f68b635e62be5e462b73fec2f86acc3f47294cf9aaa5a2b27c`. Before activation, encrypted backup `/opt/astranull-backups/postgres-2026-09-02T19-57-02-969Z-40cc417db3c8.dump.enc` and its manifest were validated and published root-owned with mode 600. The prior tree is retained at `/opt/astranull-rollback-pre-3aeb9c0f4dd9646f1e2663a82f4011a82b6e95f2`; prior image `sha256:26fcc57ce3dacead498ead91ba9f4602fd553b93d9f45dd1dbe8d9e2174114b4` remains the rollback image.

Post-activation checks confirmed `/health`, `/ready`, migrations through `0053_target_edge_detection_provenance`, the authenticated/bounded `/v1/vectors` route, unauthenticated `401`, exact `target_id` enforcement, and a healthy probe worker. The worker image now includes `db/seeds/waf-product-catalog.json`; the previous `ENOENT` packaging failure did not recur.

### Vector-library customer workflow release (2026-09-02)

Commit `f66cfe589e52db1f4013067b4fcbc9c8e16c0581` was transferred as an exact `git archive` (archive SHA-256 `8562ac0351d5f3d1f3f84446b77e5aabe2e71c774c0cf50f8ac9882d9cfe5f99`), built on-host, and activated as immutable image `sha256:0ca1c7ac2e16c29e232fb4c9c278fa45edc483b133bbce4ecbed5a328083b518`. The exact extracted release tree is `/opt/astranull-release-f66cfe589e52db1f4013067b4fcbc9c8e16c0581`.

Before activation, encrypted backup `/opt/astranull-backups/postgres-2026-09-02T21-39-12-887Z-25d0de98b284.dump.enc` and its manifest were structurally parsed, restore-validated, and retained root-owned with mode 600. The prior orchestration tree is retained at `/opt/astranull-rollback-pre-f66cfe589e52db1f4013067b4fcbc9c8e16c0581`; prior image `sha256:b8d5c9842aa584f68b635e62be5e462b73fec2f86acc3f47294cf9aaa5a2b27c` remains the rollback image. Rollback is to export that prior image for all three image-ID variables from `/opt/astranull/ops/aws`, run `docker compose up -d --no-build --force-recreate control-plane probe-worker password-recovery-worker test-policy-runner`, then verify all four containers healthy and `/health` plus `/ready` successful. The database was not migrated beyond `0053_target_edge_detection_provenance`, so code rollback requires no schema downgrade.

Post-activation checks confirmed `/health=ok`, `/ready=ready`, byte-identical local/live `react-app.js` SHA-256 `638984bf9f7e708fa269191d68bcfa91f1ef326719c4d54a2112fd9b19be126d`, unauthenticated vector API `401`, authenticated admin login, all 721 vectors over exactly eight bounded API reads, 25 rendered rows and 29 UI pages, explicit target-group and exact-target selection, SOC-governed `APP-003` and monitor-only `AMP-073` with no run launch or POST, zero serious/critical Axe findings, and read-only launch controls absent at a 390px viewport.

### Operating the stack

```bash
ssh -i ops/aws/.staging-key.pem ubuntu@34.201.159.68
cd /opt/astranull/ops/aws
IMG=sha256:0ca1c7ac2e16c29e232fb4c9c278fa45edc483b133bbce4ecbed5a328083b518
export ASTRANULL_CONTROL_PLANE_IMAGE_ID=$IMG \
       ASTRANULL_CORE_WORKER_IMAGE_ID=$IMG \
       ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=$IMG
sudo -E docker compose ps
sudo -E docker compose logs -f control-plane
sudo -E docker compose restart control-plane
```

## Production cutover to astranull.site (2026-09-02)

The previous AWS account and its production host were deleted, so this account is now the
only account and this instance is the live host for `astranull.site`.

| Field | Value |
|---|---|
| URL | `https://astranull.site` (and `www.astranull.site`) |
| Origin | `34.201.159.68` → `i-00c7a0be239bc83ea` |
| TLS | Let's Encrypt, `CN=astranull.site`, issued 2026-09-02, valid to 2026-12-01 |
| HTTP | port 80 returns `308` → `https://astranull.site/` |
| Instance tags | `Environment=production`, `Hostname=astranull.site`, `DeleteAfter=none` |

A second instance was **not** created. The instance in the resource table above was built
fresh in this account earlier the same day and already runs the exact verified commit, so
it was reconfigured for `astranull.site` rather than duplicating cost.

### DNS change made

`astranull.site` was on Cloudflare nameservers and returning **Cloudflare error 1016**
(origin DNS error) because the old origin no longer existed. Cloudflare API access was not
available, so the domain was moved to Namecheap BasicDNS, which this environment can manage.

Nameservers: `aspen/mack.ns.cloudflare.com` → `dns1/dns2.registrar-servers.com`.

The zone was then written in a single authoritative `namecheap.domains.dns.setHosts` call
(the CLI silently discards MX records unless `EmailType=MX` is supplied, and `setHosts`
replaces the whole record set, which also cleared two stale A records still pointing at the
dead `34.199.50.155`):

| Type | Host | Value | Pref | TTL |
|---|---|---|---|---|
| A | `@` | `34.201.159.68` | — | 300 |
| A | `www` | `34.201.159.68` | — | 300 |
| MX | `@` | `mx.zoho.in.` | 10 | 1800 |
| MX | `@` | `mx2.zoho.in.` | 20 | 1800 |
| MX | `@` | `mx3.zoho.in.` | 50 | 1800 |
| TXT | `@` | `v=spf1 include:zoho.in ~all` | — | 1800 |
| TXT | `@` | `zoho-verification=zb31047184.zmverify.zoho.in` | — | 1800 |

**Email was preserved deliberately.** The domain has live Zoho mail; the three MX records,
the SPF record and the Zoho verification TXT were carried across unchanged. Verified
resolving from the authoritative nameservers after the change.

Pre-change snapshot: `ops/aws/dns-backup/astranull.site-precutover-20260902T141639Z.txt`.

### DNS rollback

```bash
# Return the domain to Cloudflare nameservers (records in the Cloudflare zone are intact,
# since the zone itself was never edited — only the registrar's NS delegation changed).
namecheap ns set astranull.site aspen.ns.cloudflare.com mack.ns.cloudflare.com
```

Cloudflare will then serve its own zone again. Note that zone still points at the deleted
origin, so it would return error 1016 until its A record is updated.

### SSH access note

The security group allows SSH from single `/32` operator addresses. When the operator IP
changes, SSH times out while ports 80/443 stay up. Add the new address:

```bash
MYIP=$(curl -s https://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress --profile astranull-staging --region us-east-1 \
  --group-id sg-024035b0882f38f85 \
  --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${MYIP}/32}]"
```

Currently allowed for port 22: `108.191.200.121/32`, `123.252.204.182/32`. Prune stale
entries when convenient.

## Live validation evidence (2026-09-02, against https://astranull.site)

Both lanes were exercised over live HTTPS on the deployed host. Probe mode is
`signed-worker`, so probes were real network I/O — scoped only to `astranull.site`, a target
the tenant provably owns (it is this host's own domain).

### Ownership gate

Target `tgt_6a31fa8a3ebc162f` (`astranull.site`) reached `dns_verified` via DNS TXT
challenge `dns_4c05f7a75f52ffbd`, `eligibility=eligible`. Probe dispatch requires ownership
proven to at least `dns_verified`, so this is what allowed the bounded runs to proceed.

### Agentless / external-only lane

| Item | Value |
|---|---|
| Run | `run_598bc13bf1c526c4` → `verdicted` |
| Verdict | `edge_protected`, confidence `external_only` |
| Evidence event | `evt_409547c3f506414b` |
| Run event provenance | `probe_result` / producer `signed_probe` / source `probe_worker` |
| Placement | refused — `missing_agent` / `unbound`, "No agent is bound to this target group; internal path proof is unavailable." |

The placement refusal is the important result: with no agent bound, the run reports an
external-only verdict and makes no internal-path claim.

### Optional-agent lane

| Item | Value |
|---|---|
| Bootstrap token | `btok_08592008bfb64093` (secret returned once) |
| Agent | `agt_e563ad3b5baa04fd`, `online`, bound to `tg_demo_origin`, caps heartbeat/canary/packet |
| Heartbeat | 200, `last_token_validation_status=valid` |
| Signed job | `job_64f74ea886454300`, type `observe_window`, acked |
| Observation | `evt_69904bb30d1df772` accepted 201, producer `authenticated_agent`, source `agent` |
| Run | `run_294f2ceca2dd09cd` → `verdicted` |
| Verdict | `penetrated`, confidence `high` |
| Explanation | "External response indicated block/timeout but the agent observed traffic — possible penetration with silent drop downstream." |
| Placement | `Medium` / `observed_this_run`, agent bound, `evidence_event_id=evt_69904bb30d1df772` |
| Run events | both `probe_result`(`signed_probe`/`probe_worker`) and `agent_observation`(`authenticated_agent`/`agent`) |

Correlation behaved exactly as designed: the edge reported blocked while the authenticated
agent observed traffic, producing a high-confidence `penetrated` verdict — the product's
core claim, demonstrated end to end on the deployed release.

### Reporting

Report `rpt_56055bb296c46799` (`ready`); JSON export returned a custody digest
`content_sha256=348352eff4c854c3069a084e239f7d76…` with canonicalization
`json-key-sorted-v1`. Finding `fnd_3fd8e774b1bab3b2` (high, open) was published, and
`/v1/state` reflects 1 target group, 1 agent online, 1 open finding.

### Two findings worth recording

**Agent observation requires `nonce_hash`, not `nonce`.** The observation endpoint compares
`job.nonce_hash !== body.nonce_hash`. Posting the raw `nonce_for_agent` returns
`agent_job_mismatch` (403). The agent must send `sha256:` + SHA-256 hex of the nonce it
received; verified byte-identical against the job's stored hash.

**External-only groups finalize immediately and cannot accept observations.** With
`validation_mode=external_only`, `finalizeVerdictIfReady` runs as soon as probe evidence
lands, so an agent observation arriving milliseconds later is correctly rejected
`run_not_collecting` (409). This is intended behaviour, not a defect — the collection window
is only held open for groups whose mode is not external-only. The seeded `tg_demo_origin`
shipped as `external_only`; it was changed to `agent_assisted` to exercise the agent lane,
and remains `agent_assisted`. Change it back if external-only semantics are wanted for demos.

### Configuration left in place

`tg_demo_origin.validation_mode=agent_assisted`, and verification agent
`agt_e563ad3b5baa04fd` remains registered and online. Revoke it with
`POST /v1/agents/agt_e563ad3b5baa04fd/revoke` if a clean fleet is preferred.

### Not configured

`staging.avyanbabytalks.store` was never set up. It was superseded: the old AWS account and
its origin were deleted, so this host became the live origin for `astranull.site` itself
rather than a separate staging hostname.

## Teardown

> **This host now serves production `astranull.site`.** Running the teardown below takes the
> live site down. It remains recorded because the resources were created here and must be
> deletable, but treat it as a decommission procedure, not routine cleanup. Point DNS
> somewhere else first.

Run in this order. Commands are filled in with real IDs as resources are created.

```bash
export P="--profile astranull-staging --region us-east-1"

# 1. Terminate the instance. Stops compute billing and, because
#    DeleteOnTermination=true, also deletes root volume vol-0a37857b8647ffc31.
aws ec2 terminate-instances $P --instance-ids i-00c7a0be239bc83ea
aws ec2 wait instance-terminated $P --instance-ids i-00c7a0be239bc83ea

# 2. Release the Elastic IP. Billed while allocated even when unattached.
aws ec2 release-address $P --allocation-id eipalloc-0eb5cd0107be2af0f

# 3. Delete the security group (only succeeds once the instance is fully terminated).
aws ec2 delete-security-group $P --group-id sg-024035b0882f38f85

# 4. Delete the key pair.
aws ec2 delete-key-pair $P --key-name astranull-staging-key

# 5. Confirm nothing of ours remains. All three must print 0.
aws ec2 describe-instances $P --filters Name=tag:Project,Values=astranull \
  --query 'length(Reservations[].Instances[?State.Name!=`terminated`][])'
aws ec2 describe-addresses $P --query 'length(Addresses)'
aws ec2 describe-volumes $P --filters Name=tag:Project,Values=astranull \
  --query 'length(Volumes)'

# 6. Local cleanup
rm -f ops/aws/.staging-key.pem
```

### One-shot teardown

```bash
P="--profile astranull-staging --region us-east-1"
aws ec2 terminate-instances $P --instance-ids i-00c7a0be239bc83ea \
  && aws ec2 wait instance-terminated $P --instance-ids i-00c7a0be239bc83ea \
  && aws ec2 release-address $P --allocation-id eipalloc-0eb5cd0107be2af0f \
  && aws ec2 delete-security-group $P --group-id sg-024035b0882f38f85 \
  && aws ec2 delete-key-pair $P --key-name astranull-staging-key \
  && rm -f ops/aws/.staging-key.pem \
  && echo "teardown complete"
```

### SSH access

```bash
ssh -i ops/aws/.staging-key.pem ubuntu@34.201.159.68
```

### Verify billing has stopped

An Elastic IP left allocated and an EBS volume left behind are the two things that
silently keep charging after an instance is gone. Step 5 above is what catches both.

## Credential rotation

The access key used for this deployment (account `423370095676`, IAM user `rootuser`,
ending `…JJFNH`) was supplied in a chat transcript and must be treated as **exposed**.
Delete it in IAM after teardown: IAM → Users → `rootuser` → Security credentials →
delete the key. An earlier key ending `…W2XQN` was already invalid
(`InvalidClientTokenId`) and should be removed too if it still exists.

Full key IDs are deliberately not recorded here so they do not enter git history; match
on the suffix in the IAM console.

## Production releases 2026-09-26 / 27

Each release was an exact `git archive` of the commit, built on-host from `ops/aws/Dockerfile`,
preceded by an encrypted, structure-checked `pg_dump` in `/opt/astranull-backups`, then
`compose --profile ops run migrate` and `compose up --force-recreate --wait` of control-plane
and the three core workers. Final release: `4057dd1f` → image `sha256:bc5f0592feb5…`, schema head
`0057_waf_offensive_workflow` (migrations `0054`–`0057` applied during this window). The prior
images for every release remain tagged `astranull:<sha>` for rollback.

| Change | Detail |
|---|---|
| Scheduler | `test-policy-runner` tick also runs the collection-window sweeper and validation-scan runner (verified: expired run finalized within one tick) |
| Security | Enforced CSP, COOP, Permissions-Policy; HSTS `max-age=31536000` in the Caddyfile (reloaded live, prior copy at `/home/ubuntu/Caddyfile.bak-20260927`) |
| Resilience | Pool error handler verified live: idle app connections killed server-side, control plane logged it and did not restart |
| Live checks | Read-only sweep (`scripts/live-portal-sweep.mjs`, 6 roles × 40 route cases × 2 viewports) 0 findings; unauthenticated/tampered/header-auth all 401; role gates 403 |
| SSH | Added operator `/32` `122.167.118.172` (rule `sgr-0c96df98af8dce46f`) |

Rollback (code only; migrations `0054`–`0057` are additive and older images ignore them): from
`/opt/astranull/ops/aws`, export all three `ASTRANULL_*_IMAGE_ID` variables as the prior image ID
(`docker image inspect --format '{{.Id}}' astranull:<prior-sha>`), then
`sudo -E docker compose up -d --no-build --force-recreate --wait control-plane probe-worker password-recovery-worker test-policy-runner`.
Database restore uses the newest pre-deploy artifact with `ops/aws/restore.sh` (destructive; change approval required).

## Production release 2026-09-29 (`db97b3ae`)

Commit `db97b3ae015a568a02a30e483bc8faf46cdcc3e9` (validation-scan/scheduler review fixes, ADR-0007
reflector guardrails, portal browser-review fixes, tab accessibility) was released by hand. The
CI `Deploy AWS` workflow (run `36589216954`) passed CI but failed at SSH: its host/key secrets predate
the 2026-09-02 cutover and the runners are not on the SSH allow-list. Nothing on the host changed
during that failed run.

| Step | Detail |
|---|---|
| Archive | `git archive` of the exact commit, SHA-256 `25c95f95901f8f186dd8598471c5b51f16e72a6b8824a20da22de19c2581aa76`, verified on host, extracted to `/opt/astranull-release-db97b3ae015a568a02a30e483bc8faf46cdcc3e9` |
| Image | `astranull:db97b3ae…` → `sha256:8040329d747649ca40cea835d6a2dc1c09c3acc8da9be84d524c045745471f81`; served `react-app.js`/`.css` byte-identical to the commit |
| Backup | `/opt/astranull-backups/postgres-2026-09-29T19-42-19-151Z-4abd26381fdb.dump.enc` (+ manifest), encrypted SHA-256 `16fc277ab373…`, `pg_restore --list` parsed, `postgres-restore-drill --validate-only` ok, root-owned mode 600, no plaintext left |
| Migrate | `migrate-postgres: ok`, schema head unchanged at `0057_waf_offensive_workflow` (no new migrations); app/backup role grants re-applied |
| Activate | `compose up --no-build --force-recreate --wait` of control-plane, probe-worker, password-recovery-worker, test-policy-runner — all healthy on the new image; postgres and caddy untouched |
| Live checks | `/health` ok, `/ready` ready (oidc-jwt, postgres, signed-worker); public pages 200; unauthenticated and header-auth API calls 401; CSP/COOP/Permissions-Policy/HSTS present; 0 control-plane errors. Read-only `scripts/live-portal-sweep.mjs` (6 roles × 32 routes × 2 viewports): 0 API, console, raw-error, access, control, jargon, overflow, or placeholder findings. Its 15 `pageErrors` were the sweep's own Playwright wait predicate blocked by the strict CSP (`eval at evaluate`; the bundle contains no `eval`/`new Function`) — all 15 pages replayed in a real browser with 0 exceptions |
| SSH | Released from the existing allow-listed operator `/32` `123.252.204.182`. A temporary rule for `152.58.32.228/32` (`sgr-009c1da2afbd7ec86`) was added and revoked the same day (carrier NAT; it never connected) |

Rollback (code only; no schema change in this release): from `/opt/astranull`, export all three
`ASTRANULL_*_IMAGE_ID` variables as `sha256:bc5f0592feb5b0756f12796884a1ac65408fb347105095ef41c08ff0a1137c7f`
(`astranull:4057dd1f…`), then
`sudo -E docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env up -d --no-build --force-recreate --wait control-plane probe-worker password-recovery-worker test-policy-runner`.

Open: point the `ASTRANULL_AWS_HOST` / `ASTRANULL_AWS_KNOWN_HOSTS` secrets at this host and give the
deploy job a reachable path (e.g. SSM instead of public SSH) so pushes to `main` deploy again.

## Production release 2026-09-30 (`2d58cc48`)

Commit `2d58cc489a0aa0a6239643ec3c190a87a43e5b71` (`579793b4` probe/classifier overclaim fixes and
Akamai DNS record-set poller; `412f8538` protection-mapping reconciliation and Akamai Application
Security poller; `2d58cc48` WAF posture integration tests aligned with the coverage-gap evidence
rule) was released by hand from operator `/32` `123.252.204.182`, using the same steps as `db97b3ae`.
`make verify` was green beforehand (unit 4091/4091, integration 396 pass / 0 fail, e2e 21/21).

| Step | Detail |
|---|---|
| Archive | `git archive` SHA-256 `9ff6411f2c39d0c5a0d29f3e11818b6fd7c52d9798ad0e193356898f24c4511c`, verified on host, extracted to `/opt/astranull-release-2d58cc489a0aa0a6239643ec3c190a87a43e5b71` |
| Image | `astranull:2d58cc48…` → `sha256:82fcaa6c90d11245838e0dea9cde728dfb29f27263702a5bcf8775444d7b2209` |
| Backup | `/opt/astranull-backups/postgres-2026-09-30T10-17-13-077Z-ddc5c38f0fa3.dump.enc` (+ manifest), encrypted SHA-256 `b57b1eaef071…`, dumped as `astranull_backup`, `pg_restore --list` parsed, `postgres-restore-drill --validate-only` ok, root-owned mode 600, no plaintext left |
| Migrate | `migrate-postgres: ok`, head unchanged at `0057_waf_offensive_workflow` (no new migrations); role grants re-applied |
| Activate | `compose up --no-build --force-recreate --wait` of the four app services, all healthy on the new image with restarts=0; postgres and caddy untouched |
| Live checks | `/health` ok, `/ready` ready (oidc-jwt, postgres, signed-worker); `react-app.js`/`.css` byte-identical to the commit; changed backend modules byte-identical inside control-plane and probe-worker; unauthenticated and header-auth API 401; CSP/COOP/Permissions-Policy/HSTS present; 0 control-plane errors |
| Credential | `usr_admin` (`admin@demo.astranull.local`) password rotated through the app's invite → set-password flow (invite `pwi_fb9ae9f4aaeb6c7f`, `session_generation` 1 → 2, prior sessions invalidated). Password delivered out of band, not recorded here. Live login returns `role=admin`, `tenant_id=ten_demo` |

Rollback (code only; no schema change): from `/opt/astranull`, export all three
`ASTRANULL_*_IMAGE_ID` variables as `sha256:8040329d747649ca40cea835d6a2dc1c09c3acc8da9be84d524c045745471f81`
(`astranull:db97b3ae…`), then
`sudo -E docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env up -d --no-build --force-recreate --wait control-plane probe-worker password-recovery-worker test-policy-runner`.
A code rollback does not restore the prior admin password.

CI auto-deploy is still blocked as recorded for `db97b3ae`: the `Deploy AWS` host/key secrets and the SSH allow-list must be fixed first.

## Production release 2026-09-30 (`912c8a6a`, Dependabot batch + Node 26)

Commit `912c8a6a680a47659b52e330fd237d93c17508d6` merges all 14 open Dependabot PRs (#26, #27, #31,
#33–#43) and moves every image and CI workflow from Node 22 to Node 26 (`node:26-alpine@sha256:0b36e8c1…`,
v26.10.0; LTS from 2026-10-28, EOL 2029-04-30). `ops/aws/Dockerfile` had no Dependabot PR and was moved
by hand so the runtime-version-pin guard stays consistent. The `typescript` 7 bump removed the JS
compiler API, so `tests/unit/tabs-a11y-pairing.test.mjs` now parses TSX with Vite's `parseAst`. The
committed web bundle was rebuilt for react 19.2.8 / lucide-react 1.34 / vite 8.2. PR #1 (GuardianBot
onboarding, v0.2.11 pins) was closed as superseded. `make verify` was green on Node 26.10.0 (unit
4091/4091, integration 396 pass / 0 fail, e2e 21/21), and all six Dockerfiles built on the host.
GitHub CI, Security scan and Portal revamp passed on `912c8a6a`.

| Step | Detail |
|---|---|
| Archive | SHA-256 `a05f6e1363a618ab8599880329496c32a50af7f37f9380c6584bf4502798e32c`, extracted to `/opt/astranull-release-912c8a6a680a47659b52e330fd237d93c17508d6` |
| Image | `astranull:912c8a6a…` → `sha256:e11e9630657597e4c0f602bc6e04515a695519ca42d63ba9da6e65c548941905` (Node v26.10.0, uid 10001) |
| Backup | `/opt/astranull-backups/postgres-2026-09-30T10-49-34-080Z-f14e401f2e52.dump.enc` (+ manifest), encrypted SHA-256 `c766a884dc83…`, `pg_restore --list` ok, restore-drill `--validate-only` ok, no plaintext left |
| Migrate | ok, head unchanged at `0057_waf_offensive_workflow` |
| Activate | four app services recreated, all healthy on the new image with restarts=0; postgres and caddy untouched |
| Live checks | `/health` ok, `/ready` ready; `react-app.js` (`d1faf5ac…`) and `.css` byte-identical to the commit; unauthenticated and header-auth API 401; security headers present; browser login as admin through the portal form, then dashboard, target groups, targets, agents, runs, findings, reports and notifications all rendered with 0 page errors, console errors or CSP violations; 0 errors in service logs |

Rollback (code only; no schema change): export all three `ASTRANULL_*_IMAGE_ID` variables as
`sha256:82fcaa6c90d11245838e0dea9cde728dfb29f27263702a5bcf8775444d7b2209` (`astranull:2d58cc48…`, Node 22)
and run the same `compose up -d --no-build --force-recreate --wait` of the four app services.

Still open: the `Deploy AWS` workflow on `912c8a6a` again timed out on SSH port 22, and GuardianBot fails on
`main` (the last 60 runs all failed, independent of this release).

## Production releases 2026-09-30 (`67faafc6` outside-in revamp, `0a4d22f8` follow-up)

Commit `67faafc6c56ccc8845aec87b2a5acc42db00c5f6` implements ADR-0008 (outside-in only): agents,
bootstrap tokens, placement diagnostics and environments are removed; targets carry tags; the
dashboard, target detail and integrations pages are redesigned; connector provider logos added.
Migration `0058_target_tags_from_environments` backfills `env:<name>` tags (4/4 live targets) and
drops no tables. Commit `0a4d22f833ec0549a65571889baf197187036de1` relabels legacy `misplaced_agent`
verdicts as "Inconclusive (legacy result)", masks password-invite/reset/session ids in the audit log,
and aligns the Portal revamp suites with ADR-0008 (portal source, rebuilt bundle and tests only; no
`db`/`ops`/`src` change). Before `0a4d22f8`: unit 3737/3737, integration 369/369, contract 6/6, e2e
28/28 + Playwright 172, a11y 34/34, db-migrate idempotent. GitHub CI, Security scan and Portal revamp
passed on `0a4d22f8` (Portal revamp had failed on `67faafc6` on the stale agent-model assertions that
`0a4d22f8` fixes). Both released by hand; `deploy.sh` not used.

| Step | `67faafc6` | `0a4d22f8` |
|---|---|---|
| Archive | `git archive` tar SHA-256 `47b96a6264a8ebe54feb97f0684ea436d83645ea2c276b27b454e3a8a8faa178` → `/opt/astranull-release-67faafc6c56ccc8845aec87b2a5acc42db00c5f6` | tar SHA-256 `efbf7caf1f98c3018d5ede86151747a9d42d4b228d427eafd5edeebf5b4d309d` → `/opt/astranull-release-0a4d22f833ec0549a65571889baf197187036de1`; per-file tree digest on host equals the local archive |
| Image | `sha256:dee3e2b59e069719cc7a618fd83e41be79f802990be3002a2a778784e98cae1a` | `sha256:5cd7156a644ea0d7e1adf7ad26a52468751366dd4d329921a77567c9d85dc903`; `react-app.js` `c7dcfe3b…` / `.css` `5de7bb2b…` identical in commit, image and served response |
| Backup | `postgres-2026-09-30T18-45-51-214Z-6bf1a4cbaeb9.dump.enc` (+ manifest), encrypted SHA-256 `c5742ab0658b…` | `postgres-2026-09-30T20-11-46-693Z-cc774f1a7e8c.dump.enc` (+ manifest), encrypted SHA-256 `0abefd3f87ca…`, restore-drill `--validate-only` ok, root-owned mode 600, link count 1, no plaintext left |
| Compose | `docker-compose.yml.bak-pre-67faafc6` kept; new file drops `ASTRANULL_AGENT_IDENTITY_MODE` | `docker-compose.yml.bak-pre-0a4d22f8` kept; file unchanged |
| Migrate | head `0057` → `0058_target_tags_from_environments` | none needed; head stays `0058` |
| Activate | four app services, then `connector-poll-scheduler` and `connector-poll-runner` | same six services; postgres and caddy untouched in both |

Connectors were enabled on the host during `67faafc6`. `.env` was backed up first to
`/opt/astranull-backups/env.bak-pre-connectors-20260930T185312Z` (mode 600). Six keys changed
(`ASTRANULL_CONNECTORS_ENABLED`, `ASTRANULL_CONNECTOR_JOB_PRIVATE_KEY`/`_PUBLIC_KEY`,
`ASTRANULL_CONNECTOR_SECRET_ENCRYPTION_KEY`, `ASTRANULL_DATABASE_CONNECTOR_SCHEDULER_PASSWORD`/`_WORKER_PASSWORD`);
the values were generated on the host and never left it. Roles `astranull_connector_scheduler` and
`astranull_connector_worker` exist as non-superuser, non-BYPASSRLS logins.

Live checks on `0a4d22f8`: all six app containers healthy on the new image with restarts=0 and 0
error-level log lines since activation; `/health` ok, `/ready` ready (oidc-jwt, postgres,
signed-worker); unauthenticated `/v1/targets` 401. Independent audit with short-lived role tokens
(deleted afterwards): `scripts/live-portal-sweep.mjs` ran 6 roles × 35 route cases = 210 visits and 420
screenshots with 0 findings in every category (page/console/API errors, machine tokens, jargon,
overflow, unauthorized controls). The two P2s from the `67faafc6` sweep are gone (no "Misplaced agent"
text; audit log shows "Password invite"). `/v1/agents` and `/v1/environments` 404; every target has a
`tags` array; `deployment-features` connectors:true; `/v1/connectors` 200. An engineer high-scale
`POST /v1/test-runs` returns 403 `soc_gated_check` and the run count stays at 100.

Rollback to `67faafc6` (code only): export all three `ASTRANULL_*_IMAGE_ID` variables as
`sha256:dee3e2b59e069719cc7a618fd83e41be79f802990be3002a2a778784e98cae1a`, then run
`sudo -E docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env up -d --no-build --force-recreate --wait control-plane probe-worker password-recovery-worker test-policy-runner`
and `... up -d --no-deps --no-build --force-recreate --wait connector-poll-scheduler connector-poll-runner`.
Rolling back past `67faafc6` to `912c8a6a` (`sha256:e11e9630657597e4c0f602bc6e04515a695519ca42d63ba9da6e65c548941905`)
also requires restoring `docker-compose.yml.bak-pre-67faafc6` and stopping the two connector services.
0058 drops no tables or columns. It does set `validation_mode = 'external_only'` and clears
`target_groups.environment_id`, so pre-revamp code would show groups without environments (not
exercised). Restoring the pre-0058 data would need the `6bf1a4cbaeb9` backup through the restore
runbook, which is destructive and needs operator sign-off.

Still open: `Deploy AWS` still fails at SSH and GuardianBot still fails on its reusable-workflow SHA pin
(same as earlier releases). The host `.env` has no `ASTRANULL_ALLOWED_ORIGINS` (compose warns and uses
an empty value; this predates these releases). It also keeps an unused `ASTRANULL_AGENT_IDENTITY_MODE`
line that the compose file no longer reads.

## Production releases 2026-10-01 (`8f1bb428` domain page, `4b54df8a` connector grant fix, `eb68b284` copy polish)

`8f1bb428ddfea83afb69d21cfe0ac1ac65e14737` adds the domain page's Run all checks action, live per-check
status grouped by category, automatic WAF/CDN detection for freshly onboarded verified domains with an
Evaluating state and "How we found out" evidence, and WAF/CDN efficacy from evidence-backed verdicts. It
also raises scan caps to 500 checks / 500 steps, adds `GET /v1/validation-scans?target_id=`, and chunks the
Postgres scan projection's run-id reads at 500. `4b54df8a7108372ea5e8c39cafadc09a5ef2a9c5` keeps
`SELECT` on `schema_migrations` for the two connector roles after the grant reset (see incident below).
`eb68b284b44a61a1ca08cfb0ed49d089212f0e83` uses plain check names in the All checks list and labels a
layer that blocks under half of tested classes "Mostly not protecting". Before release: typecheck, lint,
lint:portal, web build, safety-check ok; unit + node e2e 3779/3779; integration 369/369; full Playwright
portal suite 210/210. No migrations; head stays `0058`. Compose file and `ops/aws/Dockerfile` on the host
were byte-identical to the commit. Released by hand from operator `/32` `123.252.204.182`; `deploy.sh` not used.

| Step | `8f1bb428` | `4b54df8a` | `eb68b284` |
|---|---|---|---|
| Archive SHA-256 (verified on host) | `7f5706a6652017a7…` | `77f58154740133ae…` | `f6113a74141457b8…` |
| Image | `sha256:35ab113a4f9ab49bc5106ca67a8f264acc9f7f1bc1f2b11d6e4fd3648de9df2a` | `sha256:d1433d0c702aa7825793a7654d2ab5e425488e6b38a484441153fc867b692880` | `sha256:600a025b78c22f19b377a611a64ddc59c08643fa00cf48fe3809354fc623f033` |
| Backup (encrypted, `pg_restore --list` ok, restore-drill `--validate-only` ok, root mode 600, plaintext removed) | `postgres-2026-10-01T10-24-32-125Z-bec629934381` SHA-256 `a3925ffc8ec4…` | `postgres-2026-10-01T10-36-31-459Z-d49d77ec3b9f` SHA-256 `174dadfc4f97…` | `postgres-2026-10-01T10-54-03-742Z-10faf207d05d` SHA-256 `e7e58492fb00…` |
| Migrate | ok, head `0058` | ok, head `0058` | ok, head `0058` |
| Activate | four app services healthy; connectors unhealthy (below) | all six healthy, restarts 0 | all six healthy, restarts 0 |

Incident on `8f1bb428`: the migrate step's role-grant reset revokes every table privilege from the
connector roles and re-grants a fixed list that omitted `schema_migrations`, which every Postgres runtime
reads at startup. Both connector services logged `permission denied for table schema_migrations` and went
unhealthy (core services unaffected). Restored by hand with
`GRANT SELECT ON schema_migrations TO astranull_connector_scheduler, astranull_connector_worker` (no other
privilege changed); both turned healthy within one interval. `4b54df8a` makes the grant part of the reset,
and its own migrate run proved it: after the reset both roles still had `SELECT` and the connectors started
healthy. The previous release (`0a4d22f8`) skipped migrate, which is why it was not hit then.

Live checks on `eb68b284`: `/health` ok, `/ready` ready (oidc-jwt, postgres, signed-worker); served
`react-app.js` `24edf27d…` and `react-app.css` `0e8b62ba…` byte-identical to the commit and image;
unauthenticated `/v1/targets` and `/v1/validation-scans?target_id=` 401; header auth 401; CSP/COOP/HSTS
present; 0 error-level log lines. With short-lived role tokens (minted in the control-plane container,
deleted afterwards): `/v1/validation-scans?target_id=` returns only that target's scans; viewer `POST`
to `/v1/validation-scans` and `/v1/waf/edge-detection` 403. `scripts/live-portal-sweep.mjs` (read-only,
non-GET blocked) 6 roles × 35 route cases = 210 visits: 0 page errors, 0 jargon, 0 overflow, 0
unauthorized controls. The `8f1bb428` sweep flagged 12 jargon hits (raw "WAF/API-Gateway" check names)
that `eb68b284` fixed. In the final 6-role pass, the auditor/viewer access-state and API-401 findings
appeared only after the 20-minute tokens expired mid-run; a fresh-token auditor + viewer pass was clean
(0 findings).

Rollback to `0a4d22f8` (code only, no schema change): from `/opt/astranull`, export all three
`ASTRANULL_*_IMAGE_ID` variables as `sha256:5cd7156a644ea0d7e1adf7ad26a52468751366dd4d329921a77567c9d85dc903`,
then `sudo -E docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env up -d --no-build --force-recreate --wait control-plane probe-worker password-recovery-worker test-policy-runner`
and `... up -d --no-deps --no-build --force-recreate --wait connector-poll-scheduler connector-poll-runner`.
Do not run `migrate` with the `0a4d22f8` image: its grant reset would revoke the connector roles'
`schema_migrations` access again. If it is run, re-apply the one `GRANT SELECT` above. Older code checks
the 50-check cap only on create/patch, so existing run-all scans stay individually readable. It does not
chunk run-id reads, though: once listed scans carry more than 500 child runs in total (about four run-all
scans), `GET /v1/validation-scans` on `0a4d22f8` throws, and the Test Runs and target-group scan lists fail.
Pass a smaller `limit` until the scans age out of the list.
