FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

RUN apk add --no-cache \
        c-ares=1.34.8-r0 \
        curl=8.20.0-r0 \
        libcurl=8.20.0-r0 \
    && setcap -r /usr/bin/caddy \
    && addgroup -S -g 10001 caddy-runtime \
    && adduser -S -D -H -u 10001 -G caddy-runtime caddy-runtime \
    && chown -R 10001:10001 /data /config

USER 10001:10001
