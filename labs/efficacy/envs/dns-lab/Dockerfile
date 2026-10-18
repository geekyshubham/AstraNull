FROM alpine:3.20

RUN apk add --no-cache bind bind-tools && \
    mkdir -p /var/bind /var/run/named /etc/bind && \
    rm -f /etc/bind/root.hints /var/bind/named.ca && \
    chown -R named:named /var/bind /var/run/named /etc/bind

COPY named.conf /etc/bind/named.conf
COPY lab.efficacy.invalid.zone /etc/bind/lab.efficacy.invalid.zone

RUN named-checkconf /etc/bind/named.conf && \
    named-checkzone lab.efficacy.invalid /etc/bind/lab.efficacy.invalid.zone

EXPOSE 53/udp 53/tcp

HEALTHCHECK --interval=2s --timeout=2s --start-period=2s --retries=5 \
    CMD dig +time=1 +tries=1 @127.0.0.1 SOA lab.efficacy.invalid || exit 1

USER named

CMD ["named", "-g", "-c", "/etc/bind/named.conf", "-u", "named"]
