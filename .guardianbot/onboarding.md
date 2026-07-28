## GuardianBot onboarding

Repository: `geekyshubham/AstraNull`

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
