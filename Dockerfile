FROM python:3.11-slim-bookworm

# Prevent Python from writing .pyc files and force unbuffered stdout/stderr streams
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Upgrade system packages to remediate base image vulnerabilities (CVEs)
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-privileged system user and group
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Install Python dependencies first for optimal Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source files
COPY . .

# Create volume data directory and transfer ownership to non-root user
RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Switch to non-root execution context
USER appuser

# Launch the Discord bot process
CMD ["python", "main.py"]