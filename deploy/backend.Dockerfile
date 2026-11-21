# The netlog API and the live syslog listener, in one image.
#
# Built in two stages: the first installs the package and its dependencies into a virtual
# environment; the second copies only that environment, the demo scenarios and the latest
# accuracy results onto a clean Python image. No compiler, no pip cache, no tests, no
# source checkout beyond the installed package.
#
# Built by deploy/compose.yaml from the repository root:
#   docker compose -f deploy/compose.yaml up -d --build

ARG PYTHON_IMAGE=python:3.12-slim

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
WORKDIR /src
COPY pyproject.toml README.md ./
COPY backend/netlog backend/netlog
RUN /opt/venv/bin/pip install . \
    && /opt/venv/bin/pip uninstall --yes pip setuptools wheel \
    && find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +

FROM ${PYTHON_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Everything that changes lives in /data, the named volume.
    NETLOG_DB_PATH=/data/netlog.db \
    NETLOG__API__UPLOAD_DIR=/data/uploads \
    NETLOG__RULES__USER_FILE=/data/rules.toml \
    # Inside the container the listener must accept messages from outside it. What can
    # reach it is decided by which host address the port is published on (compose.yaml).
    NETLOG__LIVE__BIND=0.0.0.0 \
    NETLOG__LIVE__PORT=5514

# A fixed user id, so the files in the volume keep one owner across upgrades.
RUN groupadd --system --gid 10001 netlog \
    && useradd --system --uid 10001 --gid netlog --no-create-home --shell /usr/sbin/nologin netlog \
    && mkdir -p /data/uploads \
    && chown -R netlog:netlog /data

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
# The demo scenarios (and their stored explanations, when there are some) and the latest
# accuracy results. The settings name them by these relative paths.
COPY data/scenarios data/scenarios
COPY eval/results/latest.json eval/results/latest.json

USER netlog
VOLUME ["/data"]
EXPOSE 8000 5514/udp 5514/tcp

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]

CMD ["uvicorn", "netlog.api.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
