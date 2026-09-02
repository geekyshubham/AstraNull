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
| Image | built from the deployed commit on the host, `sha256:26fcc57c…` |

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

### Deviation from the standard deploy path

`ops/aws/deploy.sh` was **not** used. It requires the host to be a clean git checkout
with an `origin/main` remote, and it refuses to run when any tracked file is modified —
but the staging hostname must be written into the tracked `ops/aws/Caddyfile` for TLS to
work, and the release was transferred as a `git archive` (no `.git`). The stack was
therefore brought up with Docker Compose directly, using an image built from
`ops/aws/Dockerfile` on the exact deployed tree — the same Dockerfile and build input
`deploy.sh` uses. What is skipped: the pre-migration encrypted backup, image-identity
journalling, and release-state tracking. Acceptable for a disposable staging box with no
data to lose; **not** a substitute for `deploy.sh` on a real host.

### Operating the stack

```bash
ssh -i ops/aws/.staging-key.pem ubuntu@34.201.159.68
cd /opt/astranull/ops/aws
IMG=sha256:26fcc57ce3dacead498ead91ba9f4602fd553b93d9f45dd1dbe8d9e2174114b4
export ASTRANULL_CONTROL_PLANE_IMAGE_ID=$IMG \
       ASTRANULL_CORE_WORKER_IMAGE_ID=$IMG \
       ASTRANULL_CONNECTOR_WORKER_IMAGE_ID=$IMG
sudo -E docker compose ps
sudo -E docker compose logs -f control-plane
sudo -E docker compose restart control-plane
```

## Teardown

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
