FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies (cache-optimized)
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project --no-dev --frozen --extra gcs

# Copy source code
COPY src/ ./src/
COPY cmd/ ./cmd/
COPY schema/ ./schema/
RUN uv sync --no-dev --frozen --extra gcs

ENV PYTHONPATH=/app/src

ENTRYPOINT ["uv", "run", "trace"]
CMD ["crawl-batch"]
