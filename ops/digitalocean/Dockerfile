# DigitalOcean App Platform: Postgres-backed control plane + React UI.
# Base image pinned by digest for reproducible builds. Dependabot keeps this current
# (see .github/dependabot.yml); do not replace with a floating tag.
FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4

LABEL org.opencontainers.image.title="AstraNull Control Plane (DigitalOcean)"
LABEL org.opencontainers.image.description="API and React portal for astranull.site"

RUN addgroup -g 10001 -S astranull \
  && adduser -u 10001 -S astranull -G astranull

WORKDIR /app

# `npm ci` installs exactly the lockfile's resolved versions and fails if
# package.json and package-lock.json disagree. The lockfile is copied without a
# glob so a missing lockfile breaks the build instead of silently floating.
#
# The global npm pin is kept from the GuardianBot base-image update: it fixes the
# npm shipped in the base layer, so the resolver itself is a pinned version rather
# than whatever the image happens to carry. Both halves matter — the pin fixes the
# tool, the lockfile fixes what the tool installs.
COPY package.json package-lock.json ./
RUN npm install --global npm@11.18.0 \
  && npm ci --omit=dev \
  && npm cache clean --force

COPY src ./src
COPY scripts ./scripts
COPY apps/web ./apps/web
COPY docs/api.md ./docs/api.md
COPY db/schema.sql ./db/schema.sql
COPY db/migrations ./db/migrations
COPY ops/staging ./ops/staging
COPY workers ./workers

USER astranull

ENV NODE_ENV=production \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "scripts/railway-staging-start.mjs"]
