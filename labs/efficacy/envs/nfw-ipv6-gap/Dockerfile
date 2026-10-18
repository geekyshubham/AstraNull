FROM nginx:1.27-alpine
RUN apk add --no-cache iptables ip6tables
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80 8080
ENTRYPOINT ["/entrypoint.sh"]
