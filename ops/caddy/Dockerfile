FROM caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d

RUN setcap -r /usr/bin/caddy \
    && addgroup -S -g 10001 caddy-runtime \
    && adduser -S -D -H -u 10001 -G caddy-runtime caddy-runtime \
    && chown -R 10001:10001 /data /config

USER 10001:10001
