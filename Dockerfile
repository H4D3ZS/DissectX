# DissectX - Professional Bug Bounty & Security Assessment Framework
# Deployed on Kali Linux for Industrial-grade Automation

# Stage 1: Frontend Build
FROM node:20-slim as frontend-builder
WORKDIR /web/client
COPY src/web/client/package*.json ./
RUN npm install
COPY src/web/client/ ./
RUN npm run build

# Stage 2: Final Production Image
FROM kalilinux/kali-rolling

# Set metadata
LABEL maintainer="DissectX Tooling <security@dissectx.io>"
LABEL description="All-in-one Automated Bug Bounty Management System"

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install Kali Linux Security Arsenal & Core Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    sqlmap \
    nuclei \
    nikto \
    ffuf \
    curl \
    git \
    file \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application and requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code
COPY . .

# Copy production frontend build from Stage 1
COPY --from=frontend-builder /web/client/dist /app/src/web/client/dist

# Expose ports (8000 for web interface)
EXPOSE 8000

# Set up persistence volume for scan results
VOLUME ["/root/.dissectx_scans"]

# Entrypoint starts the All-in-one Web Server
ENTRYPOINT ["python3", "main.py", "--web"]
