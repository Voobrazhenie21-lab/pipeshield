# VULNERABLE DEMO DOCKERFILE (For PipeShield Testing)
# Violations:
# 1. Unpinned base image (:latest) [PS-DOCK-002]
# 2. Hardcoded secret in ENV [PS-DOCK-003]
# 3. Insecure curl | sh pipe [PS-DOCK-004]
# 4. Use of ADD instead of COPY [PS-DOCK-005]
# 5. Missing non-root USER directive [PS-DOCK-001]
# 6. Missing HEALTHCHECK [PS-DOCK-006]

FROM python:latest

ENV API_SECRET_TOKEN=sk-live-99a8b7c6d5e4f3a2b1c0d9e8

WORKDIR /app

RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://raw.githubusercontent.com/untrusted/installer.sh | sh

ADD src/ /app/src/

CMD ["python", "/app/src/app.py"]
