FROM python:3.12-alpine
LABEL org.opencontainers.image.title="CyberForge Network Simulation Lab" \
      org.opencontainers.image.description="Loopback-only DNS/HTTP/TLS telemetry with bounded PCAP capture and process attribution" \
      org.opencontainers.image.version="1.9.5"
WORKDIR /opt/cyberforge
COPY netlab_runner.py /opt/cyberforge/netlab_runner.py
COPY netlab_telemetry.py /opt/cyberforge/netlab_telemetry.py
USER root
