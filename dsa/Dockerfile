FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY tests/ ./tests/
COPY examples/ ./examples/
COPY pyproject.toml .
COPY README.md .

# Install the package
RUN pip install -e .

# Default command runs tests
CMD ["python", "-m", "pytest", "tests/", "-v"]
