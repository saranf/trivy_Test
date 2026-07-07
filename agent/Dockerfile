# Trivy Agent Lab for MORI-SOC — agent container
# Based on the official Trivy image (alpine); adds python3 + docker-cli.
# Read-only in operation; mount the docker socket to enumerate/scan host images.
FROM aquasec/trivy:0.50.1

RUN apk add --no-cache python3 py3-yaml docker-cli

WORKDIR /opt/agent
COPY trivy_agent.py /opt/agent/trivy_agent.py
COPY config.example.yaml /opt/agent/config.yaml

# Server URL / token / agent id come from the environment at runtime:
#   MORI_SERVER_URL, MORI_AGENT_TOKEN, MORI_AGENT_ID
ENTRYPOINT ["python3", "/opt/agent/trivy_agent.py", "--config", "/opt/agent/config.yaml"]
