# AstraNull control plane (API + static UI). No secrets or database URLs baked in.
# Base image pinned by digest for reproducible builds. Dependabot keeps this current
# (see .github/dependabot.yml); do not replace with a floating tag.
FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

LABEL org.opencontainers.image.title="AstraNull Control Plane"
LABEL org.opencontainers.image.description="No-access-first DDoS readiness validation platform — API and UI"
LABEL org.opencontainers.image.source="https://github.com/astranull/astranull"
LABEL org.opencontainers.image.vendor="AstraNull"

RUN addgroup -g 10001 -S astranull \
  && adduser -u 10001 -S astranull -G astranull

WORKDIR /app

# Runtime dependencies must be installed: src/index.mjs reaches `pg` through
# src/persistence/postgres/pool.mjs, so a dependency-free image fails at import with
# ERR_MODULE_NOT_FOUND before serving a request. The lockfile is copied without a glob
# so a missing lockfile breaks the build instead of silently floating.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY apps/web ./apps/web
COPY docs/api.md ./docs/api.md
COPY db/schema.sql ./db/schema.sql

USER astranull

ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Production startup fails closed unless required runtime configuration passes src/config.mjs.
# Set database and secret settings at deployment time; never bake them into images.
CMD ["node", "src/index.mjs"]