FROM prefecthq/prefect:3.8.1-python3.13@sha256:4386a7fd80a989ab55ea98ff860f29e469f6c7b99e1a2b94eaaa7df007504ac5

ENV PREFECT_HOME=/var/lib/prefect \
    PYTHONPATH=/opt/alpha-data/backend \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 prefect \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/prefect \
        --no-create-home --shell /usr/sbin/nologin prefect \
    && install -d --owner prefect --group prefect --mode 0750 /var/lib/prefect \
    && install -d --owner prefect --group prefect --mode 0750 /opt/alpha-data/backend

COPY backend/requirements.prod.txt /tmp/alpha-data-requirements.txt

RUN pip install --no-cache-dir -r /tmp/alpha-data-requirements.txt

COPY --chown=10001:10001 backend/app /opt/alpha-data/backend/app

WORKDIR /opt/alpha-data/backend

USER 10001:10001
