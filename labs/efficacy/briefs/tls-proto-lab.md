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

Lab id: tls-proto-lab
Write only: /Users/checkred_admin/Projects/astranull/labs/efficacy/envs/tls-proto-lab/ and /tmp/astranull-lab/tls-proto-lab/
Project anl-tls-proto-lab, network anl-tls-proto-lab-net, subnet 172.31.51.0/24, internal true.

Two local endpoints, synthetic certificates you generate in the lab (throw the keys away in the lab directory, they are not secrets of any real system, but do not print them):
- 172.31.51.10:443 with an expired certificate
- 172.31.51.11:443 with a not-yet-valid certificate, or one endpoint with both conditions if that is simpler, as long as the manifest names which condition is which
Optional third listener only if it stays inside the memory cap: HTTP/2 with no advertised stream max, for protocol.http2_stream_concurrency.safe. Read that check first. If it needs a setting you cannot configure, mark not_applicable.

No handshake floods, no renegotiation loops. One openssl s_client or curl --insecure proof per endpoint is enough. Read tls.full_audit.safe before setting expectations. Self-signed is fine. Do not use a public CA.
