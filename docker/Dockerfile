# ============================================================================
# Hephaestus Production Dockerfile
# 
# Multi-stage build for minimal production image
# Usage:
#   docker build -f docker/Dockerfile -t hephaestus:0.1.0 .
#   docker run --rm hephaestus:0.1.0 --target https://example.com
# ============================================================================

FROM python:3.11-slim as builder

LABEL maintainer="Rodney Dhavid Jimenez Chacin <https://rodhnin.com>"
LABEL description="Hephaestus - Server Security Auditor"
LABEL version="0.1.0"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt /tmp/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================================================
# Production stage
# ============================================================================
FROM python:3.11-slim

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash hephaestus

# Set working directory
WORKDIR /app

# Copy application code
COPY heph/ /app/heph/
COPY config/ /app/config/
COPY templates/ /app/templates/
COPY schema/ /app/schema/
COPY db/ /app/db/
COPY assets/ /app/assets/

# Create necessary directories with proper permissions
RUN mkdir -p /reports /data && \
    chown -R hephaestus:hephaestus /app /reports /data

# Switch to non-root user
USER hephaestus

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV HEPHAESTUS_REPORT_DIR=/reports
ENV HEPHAESTUS_DATABASE=/data/argos.db
ENV HEPHAESTUS_IN_CONTAINER=true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m heph --version || exit 1

# Default entrypoint
ENTRYPOINT ["python", "-m", "heph"]

# Default command (show help)
CMD ["--help"]

# ============================================================================
# Build instructions:
#   docker build -f docker/Dockerfile -t hephaestus:0.1.0 .
#
# Run examples:
#   # Basic scan
#   docker run --rm -v $(pwd)/reports:/reports hephaestus:0.1.0 \
#     --target https://example.com
#
#   # With HTML report
#   docker run --rm -v $(pwd)/reports:/reports hephaestus:0.1.0 \
#     --target https://example.com --html
#
#   # With AI analysis (requires API key)
#   docker run --rm -v $(pwd)/reports:/reports \
#     -e OPENAI_API_KEY="sk-..." \
#     hephaestus:0.1.0 \
#     --target https://example.com --use-ai --html
#
#   # Persist database across runs
#   docker run --rm \
#     -v $(pwd)/reports:/reports \
#     -v $(pwd)/data:/data \
#     hephaestus:0.1.0 \
#     --target https://example.com
# ============================================================================