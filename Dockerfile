FROM python:3.11-slim as build

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install UV
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project configuration
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY . .

# Production image
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cerebro && useradd -r -g cerebro cerebro

WORKDIR /app

# Copy virtual environment and application
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/src /app/src
COPY --from=build /app/migrations /app/migrations
COPY --from=build /app/alembic.ini /app/alembic.ini

# Copy UV binary
COPY --from=build /bin/uv /bin/uv

# Set up environment
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH="/app/src"

# Change ownership
RUN chown -R cerebro:cerebro /app

USER cerebro

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Default command
CMD ["uvicorn", "cerebro.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
