FROM node@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
RUN apt-get update \
  && apt-get install -y --no-install-recommends iptables tcpdump iproute2 \
  && rm -rf /var/lib/apt/lists/* \
  && node --version

WORKDIR /app
COPY server.mjs /app/server.mjs
COPY healthcheck.mjs /app/healthcheck.mjs
COPY prove.mjs /app/prove.mjs

CMD ["node", "/app/server.mjs"]
