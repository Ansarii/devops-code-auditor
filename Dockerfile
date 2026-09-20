FROM python:3.12-slim

# Install git for repository cloning during audits
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Glama and MCP clients communicate over stdio
ENTRYPOINT ["python3", "server.py"]
