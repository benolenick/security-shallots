FROM python:3.12-slim

# ── Strict CPU-only: block all GPU/CUDA access ──
ENV CUDA_VISIBLE_DEVICES=-1
ENV NVIDIA_VISIBLE_DEVICES=void
ENV NVIDIA_DRIVER_CAPABILITIES=""

# Create app user with matching GIDs for log file access
# suricata=137, wazuh=136 on the host
RUN groupadd -g 1000 shallots && \
    groupadd -g 137 suricata && \
    groupadd -g 136 wazuh && \
    useradd -m -u 1000 -g shallots -G suricata,wazuh shallots

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY shallots/ ./shallots/
COPY rules/ ./rules/
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Don't copy shallots.db, GeoLite2, TLS certs, or config - they're bind-mounted

EXPOSE 8844 8855

USER shallots

CMD ["python", "-m", "shallots", "-c", "/app/config.yaml", "run"]
