FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap \
    git \
    curl \
    wget \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Go 1.21
RUN wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz && \
    rm go1.21.6.linux-amd64.tar.gz

# Set up Go environment
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:$GOPATH/bin:$PATH
ENV GO111MODULE=on

# Install security tools using Go
RUN set -eux; \
    # Install nuclei
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.1.0 || \
    (echo "Failed to install nuclei" && exit 1); \
    # Install sqlmap
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap || \
    (echo "Failed to install sqlmap" && exit 1); \
    # Install httpx
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.3.0 || \
    (echo "Failed to install httpx" && exit 1); \
    # Install subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.1 || \
    (echo "Failed to install subfinder" && exit 1)

# Update nuclei templates
RUN nuclei -update-templates || echo "Warning: Failed to update nuclei templates"

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional Python packages
RUN pip install --no-cache-dir \
    beautifulsoup4==4.12.0 \
    lxml==4.9.0 \
    requests==2.26.0 \
    python-nmap==0.7.1 \
    sslyze==5.0.0 \
    colorama==0.4.6 \
    pexpect==4.9.0

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p Logs \
    && mkdir -p /app/temp \
    && mkdir -p /app/nuclei-templates \
    && chmod -R 777 /app/temp \
    && chmod -R 777 /app/Logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV AZURE_OPENAI_API_KEY=${AZURE_OPENAI_API_KEY}
ENV AZURE_OPENAI_ENDPOINT=${AZURE_OPENAI_ENDPOINT}
ENV AZURE_OPENAI_DEPLOYMENT_NAME=${AZURE_OPENAI_DEPLOYMENT_NAME}
ENV AGENT_NAME=${AGENT_NAME}
ENV TEMP_DIR=/app/temp
ENV NUCLEI_TEMPLATES_DIR=/app/nuclei-templates

# Command to run the application
CMD ["python", "main.py"] 