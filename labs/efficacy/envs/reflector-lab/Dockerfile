FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80

WORKDIR /app

COPY server.mjs protected-server.mjs ./

EXPOSE 19/udp 1900/udp 3478/udp 6379/tcp 8080/tcp

CMD ["node", "server.mjs"]
