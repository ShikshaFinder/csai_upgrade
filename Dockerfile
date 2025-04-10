FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
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
    && rm -rf /var/lib/apt/lists/*

# Install security tools with error handling
RUN set -eux; \
    # Install nuclei
    curl -sL https://raw.githubusercontent.com/projectdiscovery/nuclei/v2.9.0/install.sh | bash || \
    (echo "Failed to install nuclei" && exit 1); \
    # Install sqlmap
    git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap || \
    (echo "Failed to install sqlmap" && exit 1); \
    # Install httpx
    curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.3.0/httpx_1.3.0_linux_amd64.tar.gz | \
    tar xz && mv httpx /usr/local/bin/ || \
    (echo "Failed to install httpx" && exit 1); \
    # Install subfinder
    curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.1/subfinder_2.6.1_linux_amd64.tar.gz | \
    tar xz && mv subfinder /usr/local/bin/ || \
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