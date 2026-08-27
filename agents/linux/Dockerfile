# AstraNull agent container — outbound-only metadata observation agent.
# Base image pinned by digest for reproducible builds. Dependabot keeps this current
# (see .github/dependabot.yml); do not replace with a floating tag.
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019

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