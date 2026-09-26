FROM python:3.12-slim-bookworm

LABEL maintainer="PipeShield DevSecOps Team"
LABEL description="PipeShield: Next-Gen DevSecOps Pipeline Security Scanner"

# Create unprivileged user to adhere to container security best practices
RUN groupadd -r pipeshield && useradd -r -g pipeshield -u 10001 -m pipeshield

WORKDIR /app

# Install dependencies and project
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

USER pipeshield

ENTRYPOINT ["pipeshield"]
CMD ["scan", "/workspace"]
