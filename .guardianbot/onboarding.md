## GuardianBot onboarding

Repository: `Geekyshubham/AstraNull`

| Capability | Detection |
| --- | --- |
| Languages | `css`, `dockerfile`, `html`, `javascript`, `makefile`, `shell`, `typescript` |
| Package managers | `pnpm` |
| Lockfiles | `pnpm-lock.yaml` |
| Dockerfiles | `Dockerfile`, `agents/linux/Dockerfile`, `ops/digitalocean/Dockerfile`, `ops/docker/Dockerfile.control-plane`, `ops/docker/Dockerfile.tooling`, `ops/kubernetes/Dockerfile.worker`, `ops/railway/Dockerfile.staging` |
| OpenAPI | `docs/api/waf-posture-openapi.json` |

### Rollout

- Scanner mode starts as **report-only**.
- Existing findings form the initial baseline.
- Enforcement is enabled separately after the observation period.
- GuardianBot infrastructure and model credentials are not copied into this repository.

### Notes

- No CODEOWNERS file detected; reviewer suggestions will use history.

## Generated reusable configuration

- Languages: `css`, `dockerfile`, `html`, `javascript`, `makefile`, `shell`, `typescript`
- Package managers: `pnpm`
- Lockfiles: `pnpm-lock.yaml`
- Source paths: `apps/web/react/src/**`, `apps/web/react/src/lib/**`, `scripts/lib/**`, `src/**`, `src/lib/**`
- Test paths: `**/*.spec.*`, `**/*.test.*`, `tests/**`
- Generated paths: none detected
- Vendored paths: none detected
- Excluded paths: `**/*.generated.*`, `**/*.map`, `**/*.min.js`, `**/.build/**`, `**/.next/**`, `**/Carthage/**`, `**/Pods/**`, `**/build/**`, `**/coverage/**`, `**/dist/**`, `**/node_modules/**`, `**/vendor/**`
- Command execution boundary: `github-hosted`
- Test commands: `pnpm test`
- Build commands: none detected
- Image coverage: configured from `ops/digitalocean/Dockerfile` for linux/amd64; GHCR, runtime smoke, CycloneDX SBOM, keyless signing, and immutable-digest promotion policy are declared
- DAST coverage: available but not configured; detected OpenAPI: `docs/api/waf-posture-openapi.json`

Detected commands are declarations executed only by the pinned reusable workflow on GitHub-hosted or ephemeral runners.

No model credentials, scanner credentials, deployment credentials, backend URLs, or shared secrets are written to this repository.