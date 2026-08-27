# AstraNull on AWS (`astranull.site`)

Single Ubuntu VM in `us-east-1f`: Postgres + control plane + Caddy (HTTPS).

Push to `main` deploys. Secrets live in `ops/aws/.env` on the instance and in GitHub Actions SSH secrets — never in git.

## Stack

| Piece | Where |
|---|---|
| VM | EC2 Ubuntu 22.04, Elastic IP |
| App | `ops/aws/Dockerfile` (migrate, seed, API, probe worker) |
| DB | Postgres 16 on the same VM |
| TLS | Caddy → Let's Encrypt for `astranull.site` / `www` |
| DNS | Namecheap A records → Elastic IP |

## GitHub secrets

Repo **Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `ASTRANULL_AWS_HOST` | Elastic IP of the VM |
| `ASTRANULL_AWS_USER` | `ubuntu` |
| `ASTRANULL_AWS_SSH_KEY` | Private key whose public half is in `ubuntu`'s `authorized_keys` |

## First boot (already done if you used this repo's provision)

1. Clone to `/opt/astranull`.
2. Copy `ops/aws/env.example` → `ops/aws/.env` and fill the generated secrets.
3. `bash /opt/astranull/ops/aws/deploy.sh`

## Manual deploy

```bash
ssh ubuntu@<elastic-ip> 'bash /opt/astranull/ops/aws/deploy.sh'
```

## Not in this stack

Enterprise IdP, external probe fleet, agent mTLS gateway, WAF cron workers.
