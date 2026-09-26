# AstraNull agent container — outbound-only metadata observation agent.
# Base image pinned by digest for reproducible builds. Dependabot keeps this current
# (see .github/dependabot.yml); do not replace with a floating tag.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

LABEL org.opencontainers.image.title="AstraNull Agent"
LABEL org.opencontainers.image.description="Outbound-only validation agent for AstraNull readiness checks"
LABEL org.opencontainers.image.source="https://github.com/astranull/astranull"
LABEL org.opencontainers.image.vendor="AstraNull"

RUN addgroup -g 10001 -S astranull \
  && adduser -S -u 10001 -G astranull astranull

WORKDIR /opt/astranull

COPY --chown=astranull:astranull astranull-agent.mjs ./

# The agent is a single dependency-free script; package managers never ship in the image.
RUN mkdir -p /var/lib/astranull \
  && chown -R astranull:astranull /var/lib/astranull \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg

USER astranull

ENV NODE_ENV=production \
    ASTRANULL_AGENT_IDENTITY=/var/lib/astranull/identity.json

# Operators must set ASTRANULL_API_URL (HTTPS) and mount enrollment credentials via
# ASTRANULL_BOOTSTRAP_TOKEN_FILE or a file under /var/lib/astranull.
ENTRYPOINT ["node", "astranull-agent.mjs"]