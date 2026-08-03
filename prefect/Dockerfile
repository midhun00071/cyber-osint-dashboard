FROM prefecthq/prefect:3.8.1-python3.13

ENV PREFECT_HOME=/var/lib/prefect

RUN groupadd --gid 10001 prefect \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/prefect \
        --no-create-home --shell /usr/sbin/nologin prefect \
    && install -d --owner prefect --group prefect --mode 0750 /var/lib/prefect

WORKDIR /var/lib/prefect

USER 10001:10001
