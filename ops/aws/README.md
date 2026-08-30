# AstraNull on AWS (`astranull.site`)

Single Ubuntu VM in `us-east-1f`: Postgres + control plane + isolated probe, recovery, and policy workers + Caddy (HTTPS).

A successful same-repository `push` CI run for the current `main` SHA triggers deployment. The workflow checks out that exact SHA, hashes its `ops/aws/deploy.sh`, transfers it to a unique temporary path, and requires the VM to verify the hash before execution; it never trusts a potentially stale host copy of the script. The VM rejects stale SHAs, dirty checkouts, overlapping deploys, permissive `.env` files, failed encrypted backups, unhealthy workers, and failed internal or public health checks. Secrets live in `ops/aws/.env` on the instance and GitHub Actions secrets—never in git.

## Stack

| Piece | Where |
|---|---|
| VM | EC2 Ubuntu 22.04, Elastic IP |
| App/workers | Image-only services in `ops/aws/docker-compose.yml`; `deploy.sh` builds `ops/aws/Dockerfile` from the exact commit archive |
| DB | Postgres 16 on the same VM |
| DB roles | Short-lived `migrate` uses owner `astranull`; runtime services use `astranull_app` (`NOBYPASSRLS`); one-shot dumps use SELECT-only `astranull_backup` (`BYPASSRLS` is required to read all FORCE-RLS rows) |
| TLS | Caddy → Let's Encrypt for `astranull.site` / `www` |
| Backups | Bounded-stream AES-256-GCM binary-v2 custom dumps + integrity manifests in `/opt/astranull-backups` (newest 10 retained); legacy v1 restore remains supported |

## GitHub secrets

| Secret | Value |
|---|---|
| `ASTRANULL_AWS_HOST` | Elastic IP of the VM |
| `ASTRANULL_AWS_USER` | `ubuntu` |
| `ASTRANULL_AWS_SSH_KEY` | Private key whose public half is in `ubuntu`'s `authorized_keys` |
| `ASTRANULL_AWS_KNOWN_HOSTS` | Pinned `known_hosts` line for the VM; obtain and verify its fingerprint out of band |

## First boot

1. Clone to `/opt/astranull` and ensure the deploy user owns the clean checkout.
2. Copy `ops/aws/env.example` to `ops/aws/.env`, fill every secret/tenant scope, and run `chmod 600 ops/aws/.env`.
3. Generate dedicated 64-hex values for `POSTGRES_PASSWORD`, `ASTRANULL_DATABASE_APP_PASSWORD`, `ASTRANULL_DATABASE_BACKUP_PASSWORD`, `ASTRANULL_BACKUP_ENCRYPTION_KEY`, and `ASTRANULL_SECRET_ENCRYPTION_KEY`. All five must be distinct; deployment preflight rejects missing, malformed, mismatched, or reused values before checkout.
4. Confirm the rendered Compose model gives `backup-dump` only the `astranull_backup` URL, gives `backup` only its encryption key (plus `NODE_ENV`), and exposes neither credential to long-lived services. The deploy script's validator enforces this automatically.
5. Create `/opt/astranull-backups` owned by the deploy user with mode `700`. The deploy script creates `/opt/astranull-backups/deploy-state` and atomically records both the verified control-plane tag and immutable Docker image ID in `control-plane-image-tag` (one line each, retained at this path for upgrade compatibility); this state deliberately lives outside the Git checkout.
6. For initial bootstrap only, invoke an exact current-main revision: `bash /opt/astranull/ops/aws/deploy.sh <40-character-sha>`. Subsequent releases use the CI workflow's verified temporary script.

Normal releases must use the CI-triggered GitHub workflow, not a manual Actions bypass. `deploy.sh` snapshots Compose independently from the target SHA and the previously deployed SHA. Normal backup, migration, and activation phases use only the target-SHA snapshot; the previous snapshot is reserved for explicit or automatic rollback. The AWS Compose file is image-only for the control plane, workers, and one-shot ops services: it contains no `build`, build `context`, or `dockerfile` keys, so `docker compose up` cannot turn the host checkout into a release image. `deploy.sh` is the sole AWS control-plane build path and builds only from `git archive` of the requested exact SHA, never from the orchestration worktree, so ignored or untracked host files cannot enter the release image. On a genuinely fresh host—no Postgres service container and no Compose `pgdata` volume—the script starts only Postgres and waits for its health check. If a container exists it is health-checked without an `up`; if a data volume exists without its container, deployment fails closed for operator recovery. Before the encrypted dump, a one-shot target-image bootstrap creates or rotates only the SELECT-only `astranull_backup` role; it neither applies migrations nor starts runtime services. The backup then completes and is verified before the profile-gated migration service applies migrations and atomically creates/rotates `astranull_app` plus `astranull_backup`. Thus existing application data and schema are backed up before any target migration or runtime activation. The app role gets runtime DML with `NOBYPASSRLS`; the backup role has its ACLs reset to SELECT-only and receives `BYPASSRLS` solely because complete dumps of FORCE-RLS tables otherwise omit or reject tenant rows.

The exact-commit build contract remains `git archive "$SHA" | docker build ... -`; it must never fall back to the orchestration worktree. The AWS Dockerfile is referenced by the deploy helper, not by Compose. [`release-archive-inputs.txt`](release-archive-inputs.txt) indexes every `ops/aws/Dockerfile` `COPY` source plus runtime-critical leaves such as `scripts/worker-heartbeat-health.mjs` and the vendored notices. The executable unit contract inspects the real `HEAD` archive. During the current pre-commit worktree only, an intended untracked input may produce an explicit diagnostic instead of pretending it is already in `HEAD`; every such path **must be tracked in the final commit**, and a clean CI checkout fails if it is absent. This AWS boundary does not change the repository-root `docker-compose.yml`, which remains the separate local non-AWS build workflow.

The hosted test-policy scheduler accepts only 5–30 second intervals (default and maximum 30). Each successful invocation is bounded to 120 seconds, so the longest valid success-plus-sleep cycle is 150 seconds—30 seconds inside the 180-second heartbeat freshness window. The heartbeat is written only after a successful tick; failed or timed-out ticks leave it unchanged, allowing sustained failures to become unhealthy, while `restart: unless-stopped` retains process-exit restart behavior.

### Backup handoff contract for deploy/rollback automation

The shell owner must use these three boundaries in order. `pg_dump` must **not** run through `exec postgres`, as `-U astranull`, or inside the encryption service. With the deploy script's existing bounded Compose wrapper and `/opt/astranull-backups` mount, the command contract is:

```bash
# 0. First-upgrade-safe role setup. This changes only the dump role and grants; it does
# not apply migrations or start a runtime service.
compose_timeout 90 --profile ops run --rm --no-deps backup-role-bootstrap

# 1. Dump as the read-only backup role. The service receives only its backup DB URL.
compose_timeout 180 --profile ops run --rm --no-deps \
  -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup-dump \
  sh -eu -c 'umask 077; exec pg_dump --format=custom --no-owner --no-acl \
    --dbname="$ASTRANULL_BACKUP_DATABASE_URL" --file="$1"' sh "/backup/$plain_name"

# 2. Stream-encrypt that file. This service receives only the backup encryption key.
compose_timeout 180 --profile ops run --rm --no-deps \
  -u "$(id -u):$(id -g)" -v "$BACKUP_DIR:/backup" backup \
  node scripts/postgres-backup.mjs --input "/backup/$plain_name" --out /backup \
    --label "predeploy-${previous:0:12}" \
    --database-host postgres --database-port 5432 --database-name astranull
```

The automation must then run `postgres-restore-drill.mjs --validate-only` against the encrypted artifact, delete the plaintext in its existing failure/exit trap, and only then migrate. `postgres-backup.mjs` refuses a production direct-dump URL unless its user is `astranull_backup`; input mode accepts no DB URL. `postgres-restore-drill.mjs` accepts only the encryption key and manifest/artifact paths. `deploy.sh` implements this exact handoff, validates the encrypted artifact, and removes the plaintext before migration; hosted promotion fails closed if any boundary fails.

Verify role posture after deployment without printing credentials:

```bash
docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env exec -T postgres \
  psql -U astranull -d astranull -v ON_ERROR_STOP=1 -c \
  "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolinherit, rolbypassrls FROM pg_roles WHERE rolname IN ('astranull_app','astranull_backup') ORDER BY rolname;"
docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env exec -T postgres \
  psql -U astranull -d astranull -v ON_ERROR_STOP=1 -c \
  "SELECT r.rolname, count(*) AS owned_tables FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname IN ('astranull_app','astranull_backup') AND c.relkind IN ('r','p') GROUP BY r.rolname;"
docker compose -f ops/aws/docker-compose.yml --env-file ops/aws/.env exec -T postgres \
  psql -U astranull -d astranull -v ON_ERROR_STOP=1 -c \
  "SELECT privilege_type, count(*) FROM information_schema.role_table_grants WHERE grantee='astranull_backup' GROUP BY privilege_type ORDER BY privilege_type;"
```

Expected: neither role is superuser/creator/owner; `astranull_app` has `rolbypassrls=f`; `astranull_backup` has `rolbypassrls=t`, `rolinherit=f`, and only `SELECT` table grants.

## Rollback

Every successful deploy prints the prior exact revision and encrypted backup artifact. Code rollback is explicit:

```bash
bash /opt/astranull/ops/aws/deploy.sh --rollback <prior-40-character-sha>
```

Rollback candidates must be ancestors of `origin/main`; the restored stack is health-checked. An explicit rollback builds the selected ancestor from `git archive` without moving the current checkout, so Compose and all workers remain on the current orchestration release while only the control-plane image changes. After health verification, the actual control-plane tag and immutable image ID are atomically persisted in `/opt/astranull-backups/deploy-state/control-plane-image-tag`. A later failed deployment reads that external identity, verifies the old ID still exists locally, and rebinds the previous tag to that ID **before** Compose activation. This is required when a normal or rollback build reused the same SHA tag and moved it to a new image ID; it also preserves hybrid releases where the control-plane tag differs from the orchestration/worker tag. The restored control-plane container ID is checked against the captured ID, while workers continue to follow the selected orchestration tag. Database migrations are not automatically reversed. A failed deployment reports when migrations may have advanced and identifies the encrypted predeploy backup. Forward migrations retain previous-release write contracts throughout their rollback windows: migration `0044` fills target values omitted by the old writer, and migration `0045` accepts old `event_driven` policy writes only through a compatibility trigger plus CHECK that force them paused, disabled, and unscheduled. The current application contract and scheduler continue to omit that cadence.

## Governed database restore

A restore is destructive and causes an outage. Run it only with explicit incident/change approval, after recording the encrypted backup and manifest paths. Before stopping anything, the executable wrapper acquires the same lock as deployment, requires the persisted control-plane tag+ID record, resolves the immutable ID itself, and rebinds the mutable tag to it. This applies to running and fully stopped stacks; restore fails closed before database work when the expected image is missing rather than trusting whatever the tag currently names. It then validates five-way secret separation, stops all readers/writers and ingress, asks the credential-free `backup` service to stream-validate encrypted and plaintext SHA-256 values, authenticate AES-256-GCM, check the `PGDMP` header, and exclusively materialize a mode-0600 archive. It refuses plaintext overwrite, runs bounded restore/migration commands, verifies the restored container ID and unchanged external state, and removes plaintext through an `EXIT` trap. On failure, runtime services stay stopped for investigation.

```bash
cd /opt/astranull
bash ops/aws/restore.sh --yes \
  /opt/astranull-backups/<backup>.dump.enc.manifest.json \
  /opt/astranull-backups/<backup>.dump.enc
```

After verification and while services remain stopped, the wrapper connects to the `postgres` maintenance database, terminates straggling sessions, drops `astranull`, and recreates it from `template0`. It then runs `pg_restore --single-transaction --exit-on-error --no-owner --no-acl` into that empty database, reapplies migration head and transactional app-role grants, removes plaintext, and waits for service health. Recreating the database is required: `pg_restore --clean` removes only objects represented in the archive and can leave post-backup objects behind as a hybrid schema.

Before closing the change, independently verify `/health`, `/ready`, all worker heartbeat health states, migration head, `astranull_app` posture/zero ownership, tenant RLS smoke tests, login, and portal reads. Retain the encrypted artifact and manifest; never retain or copy the plaintext dump.

## Not in this stack

Enterprise IdP onboarding evidence, a production multi-region probe fleet, agent mTLS gateway, and certified governed high-scale adapters remain separately tracked production-release gates. The Compose `probe-worker` is the isolated reference worker for this host, not evidence of a multi-region production fleet.
