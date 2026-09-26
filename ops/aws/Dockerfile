# AstraNull control plane for the AWS VM (API + React UI + probe worker).
# Base image pinned by digest for reproducible builds. Dependabot keeps this current
# (see .github/dependabot.yml); do not replace with a floating tag.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

LABEL org.opencontainers.image.title="AstraNull Control Plane"
LABEL org.opencontainers.image.description="API and React portal for astranull.site"

RUN addgroup -g 10001 -S astranull \
  && adduser -u 10001 -S astranull -G astranull

WORKDIR /app

COPY package.json package-lock.json ./
# npm is only needed to install; it is removed so its bundled dependencies never ship
# in the runtime image (nothing at runtime invokes npm/npx/yarn).
RUN npm install --global npm@11.18.0 \
  && npm ci --omit=dev \
  && npm cache clean --force \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY src ./src
COPY scripts ./scripts
COPY apps/web ./apps/web
COPY docs/api.md ./docs/api.md
COPY db/schema.sql ./db/schema.sql
COPY db/migrations ./db/migrations
COPY db/seeds/waf-product-catalog.json ./db/seeds/waf-product-catalog.json
COPY THIRD_PARTY_NOTICES ./THIRD_PARTY_NOTICES
COPY workers ./workers

USER astranull

ENV NODE_ENV=production \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=90s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "scripts/railway-staging-start.mjs"]
