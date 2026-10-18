You are one AstraNull efficacy-lab worker. Model: Gemini 3.8 Flash High. Work only this lab.

Read first, and obey: /Users/checkred_admin/Projects/astranull/labs/efficacy/CONTRACT.md
Repo: /Users/checkred_admin/Projects/astranull
Today: 2026-10-17. Docker is Colima (10 CPU, about 14 GiB) and is already running.

Safety (hard):
- Traffic stays on the lab networks in 172.31.0.0/16 that you create. internal: true. No public targets, no scans of the host, no traffic to the internet except docker pull and image builds.
- No attack or flood tooling. No sqlmap, nikto, hping, slowloris, load generators, packet spoofing, amplification scripts, monlist, memcached stats dumps, or exploit apps (no DVWA, WebGoat, Juice Shop).
- The only request payloads you may send for a proof are the exact inert markers and bounded probes already implemented in the repo, copied from source, plus plain health requests (GET /, dig of your lab zone, a single TCP connect). Do not invent new exploit strings.
- Never push images, never docker login, never publish ports except 127.0.0.1 when the contract allows and you cannot avoid it.
- Never stop, remove, or modify containers, networks, or volumes you did not create. Do not touch names starting with bgp- or astranull-postgres-local. Prefix every resource with anl-<lab-id>.
- Repository source is read-only. Do not edit src/, workers/, tests/, scripts/, db/, docs/, apps/, ops/, PROGRESS.md, package.json, or CONTRACT.md. Write only your lab directory and /tmp/astranull-lab/<lab-id>/.
- No git commands that change state. No secrets. Synthetic data only.
- Every service: cpus at most 1.0, mem_limit at most 768m. If docker info shows little free memory, wait and retry. Do not kill other containers.
- Leave the lab RUNNING when you finish. down.sh removes only your project.

Colima fact: the Mac host cannot route to container IPs. Prove each planted condition with a throwaway container attached to your lab network (curl, nc, dig, or a single TCP connect). Remove that throwaway when the proof is recorded. Do not enable IPv6 on the Colima daemon. A network with enable_ipv6 is fine; if the daemon refuses, record the blocker and do not reconfigure Colima.

Ground truth is the lab config, not AstraNull. In manifest expectations, use expected protected, gap, not_applicable, or inconclusive_expected only for checks whose behavior you proved or that you read in source and can justify. Do not invent a long guess list. Read the check definition and the probe it sends before you name it.

Done: STATUS.md updated, REPORT.md with image ids (docker image inspect --format '{{.Id}}'), health proof, and limitations. Your final message is at most 25 lines. No secrets.

Lab id: harness
Write only: /Users/checkred_admin/Projects/astranull/labs/efficacy/harness/ and /tmp/astranull-lab/harness/
Compose project anl-harness, subnet 172.31.10.0/24, network name anl-harness-net.

Build labs/efficacy/harness/run-checks.sh exactly as the contract specifies:
  run-checks.sh --manifest <path> [--checks id1,id2 | --prefix waf.] --out <dir>
It must run real catalog checks through the local control plane and the signed probe worker, then write <out>/results.jsonl and <out>/summary.md with the confusion matrix in the contract (detected gap, missed gap, false alarm, correct protected, inconclusive).

Design you must follow:
- Do not reset, reseed, or restart astranull-postgres-local. Do not overwrite .data/astranull-dev.json. Do not kill an API you did not start.
- The host cannot reach 172.31 addresses. Lab networks are internal, so lab containers cannot reach a host API. Run the probe worker as a container on TWO networks: the target lab network (so it can dial the target) and anl-harness-net (internal false, so it can reach the API on the host via host.docker.internal or the Colima gateway). Verify that path with one curl before you write READY.
- Probe worker env: NODE_ENV is not production, ASTRANULL_PROBE_ALLOW_PRIVATE_DESTINATIONS=1. Read workers/probe-worker.mjs resolveProbeDestinationPolicy and use it. Mount the repo read-only into that container.
- Control plane: prefer an API process you start yourself on 127.0.0.1:3011 using the existing local Postgres, only if a second process will not run migrations destructively or take a lock that stops the existing stack. If that is unsafe, write the blocker in REPORT.md and do not proceed to live runs. Read src/ and scripts/ for the dev auth headers (x-tenant-id, x-user-id, x-role) and for ASTRANULL_DEMO_AUTO_VERIFY_TENANTS. Create one synthetic tenant for this lab. Set the demo auto-verify list to that exact tenant id only if you started the process. Never use a wildcard. Never print tokens.
- Create targets from the manifest (kind ip, url, tcp, or dns_zone as the check requires). PUT the manifest declarations onto the target (block signature, network_policy, connection_limits) using the documented control-declarations API. Read docs/api.md for the schema.
- Poll each test run to a terminal state. Grade the security conclusion against the manifest expected value, not against incidental field names.
- Hard filter: refuse to dispatch check ids containing offensive, high_scale, flood, slowloris, amplification as a generator, or any check whose probe kind is a volumetric readiness check. Record those as skipped_safety. The only traffic is the catalog's existing bounded safe probes.
- Do not edit product source. If a private address is rejected, cite file:line in REPORT.md.
- Write labs/efficacy/harness/READY when run-checks.sh exists, is executable, and --help works. A live smoke against a lab is required only if at least one labs/efficacy/envs/*/manifest.json exists and that lab's network is up. If none are up yet, READY may still be written after --help, and REPORT.md must say the live smoke is pending.
- Also write up.sh and down.sh for the harness network only.
