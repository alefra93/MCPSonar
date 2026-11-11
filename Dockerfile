# mcpsonar — protocol-aware health checks for MCP servers.
# Build:  docker build -t mcpsonar .
# Run:    docker run --rm -p 8675:8675 -v mcpsonar-data:/data mcpsonar
#         then open the setup link printed in `docker logs` (one-time setup token).
FROM python:3.15-slim

# No .pyc files, unbuffered logs (so container logs stream immediately).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install the package (hatchling reads README.md + LICENSE referenced in pyproject.toml).
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin mcpsonar \
    && mkdir -p /data && chown 10001:10001 /data

COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The SQLite DB lives here; docker-compose mounts a named volume so it survives restarts.
ENV MCPSONAR_DB=/data/mcpsonar.db \
    HOME=/data
VOLUME ["/data"]

# Dashboard / Prometheus /metrics port.
EXPOSE 8675

# /api/auth/status is public and touches the database: a cheap liveness probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8675/api/auth/status', timeout=4)"]

# Starts as root only to fix /data ownership, then runs mcpsonar as uid 10001 with no
# privileges (see docker-entrypoint.sh). Bind 0.0.0.0 so the dashboard is reachable from
# outside the container. Servers are added from the UI (or seeded with --config).
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["run", "--host", "0.0.0.0", "--port", "8675"]
