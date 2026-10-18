FROM golang:1.26.9-bookworm AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends python3 git
WORKDIR /src
COPY native/gateway native/gateway
COPY scripts/build-gateway.sh scripts/build-gateway.sh
RUN bash scripts/build-gateway.sh
FROM verklikker/service:0.1.0 AS service
FROM node:24-trixie-slim
WORKDIR /app
COPY --from=service /app /app
USER root
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-system-arm qemu-utils python3 python3-venv && python3 -m venv /opt/mitm && /opt/mitm/bin/pip install --no-cache-dir 'mitmproxy==12.2.1' && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/mitm/bin:$PATH RUNTIME_DIRECTORY=/opt/runtime EVIDENCE_DIRECTORY=/tmp/evidence
COPY --from=gateway /src/runtime/verklikker-gateway /opt/runtime/verklikker-gateway
COPY native/proxy.py /opt/runtime/proxy.py
ARG RUNTIME_ARCH=x64
COPY runtime/${RUNTIME_ARCH} /opt/runtime/${RUNTIME_ARCH}
RUN chown -R node:node /opt/runtime
USER node
CMD ["node","dist/apps/worker/main.js"]
