# Dockerfile for Application Container
# This container runs the application monitoring tests and analysis

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY scripts/ ./scripts/

# Create results directory
RUN mkdir -p /app/results

# Default command (can be overridden)
CMD ["python3", "--version"]
