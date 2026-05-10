FROM python:3.11-slim

LABEL org.opencontainers.image.title="depenemy"
LABEL org.opencontainers.image.description="npm supply chain security scanner"
LABEL org.opencontainers.image.source="https://github.com/W3OSC/depenemy"
LABEL org.opencontainers.image.licenses="MIT"

# Install git (needed for lockfile git-diff checks)
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Install depenemy from the repository source (build context is the repo root)
COPY . /src
RUN pip install --no-cache-dir /src

# Copy Docker action scripts
COPY action/scripts/ /scripts/
RUN chmod +x /scripts/entrypoint.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
