# Quantum Cryptography Demonstrations
# - BB84 Quantum Key Distribution
# - Shor's Algorithm Threat to RSA/ECDSA

FROM python:3.11-slim

LABEL maintainer="qkd-project"
LABEL description="Quantum cryptography: QKD simulator and Shor's algorithm threat demos"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY tests/ tests/
COPY examples/ examples/
COPY docs/ docs/

# Copy demo files if they exist
COPY demo.py* ./

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Default command: show help
CMD ["python", "-c", "print('Use: make demo-rsa, make demo-ecdsa, or make demo-qkd')"]
