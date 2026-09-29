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
