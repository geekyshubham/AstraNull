# AstraNull agent container — outbound-only metadata observation agent.
# Base image pinned by digest for reproducible builds. Dependabot keeps this current
# (see .github/dependabot.yml); do not replace with a floating tag.
FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4

LABEL org.opencontainers.image.title="AstraNull Agent"
LABEL org.opencontainers.image.description="Outbound-only validation agent for AstraNull readiness checks"
LABEL org.opencontainers.image.source="https://github.com/astranull/astranull"
LABEL org.opencontainers.image.vendor="AstraNull"

RUN addgroup -g 10001 -S astranull \
  && adduser -S -u 10001 -G astranull astranull

WORKDIR /opt/astranull

COPY --chown=astranull:astranull astranull-agent.mjs ./

RUN mkdir -p /var/lib/astranull \
  && chown -R astranull:astranull /var/lib/astranull

USER astranull

ENV NODE_ENV=production \
    ASTRANULL_AGENT_IDENTITY=/var/lib/astranull/identity.json

# Operators must set ASTRANULL_API_URL (HTTPS) and mount enrollment credentials via
# ASTRANULL_BOOTSTRAP_TOKEN_FILE or a file under /var/lib/astranull.
ENTRYPOINT ["node", "astranull-agent.mjs"]