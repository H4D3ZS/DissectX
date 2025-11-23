# DissectX - Professional Binary Analysis Framework
# Multi-stage Docker build for optimized image size

# Stage 1: Builder
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    cmake \
    git \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Set metadata
LABEL maintainer="DissectX Contributors <dissectx@example.com>"
LABEL description="Professional Binary Analysis & Reverse Engineering Framework"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/root/.local/bin:$PATH

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Set working directory
WORKDIR /workspace

# Copy application code
COPY . /app
WORKDIR /app

# Install DissectX
RUN pip install --no-cache-dir -e .

# Create workspace directory
WORKDIR /workspace

# Expose web UI port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["python", "/app/main.py"]

# Default command (show help)
CMD ["--help"]
