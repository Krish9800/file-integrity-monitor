# ==========================================
# Build Stage
# ==========================================
FROM python:3.12-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /build/
COPY src/ /build/src/

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir .

# ==========================================
# Production Runtime Stage
# ==========================================
FROM python:3.12-slim-bookworm AS production

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create non-root dedicated security service account
RUN groupadd -g 10001 fimgroup && \
    useradd -u 10001 -g fimgroup -s /sbin/nologin -M fimuser && \
    mkdir -p /data/baseline /var/log/fim && \
    chown -R fimuser:fimgroup /data /var/log/fim

COPY --from=builder /opt/venv /opt/venv

WORKDIR /data

USER fimuser

ENTRYPOINT ["fim"]
CMD ["--help"]
