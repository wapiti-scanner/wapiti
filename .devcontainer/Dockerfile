FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    ca-certificates \
    curl \
    wget \
    vim \
    nano \
    php8.4-cli \
    php8.4-xml \
    sslscan \
    && apt-get clean -yq \
    && apt-get autoremove -yq \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install system dependencies for Playwright
# (will be completed by playwright install --with-deps in postCreateCommand)
RUN apt-get update && apt-get install -y \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    && apt-get clean -yq \
    && apt-get autoremove -yq \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Update pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Set working directory
WORKDIR /workspace

# Copy project configuration files
COPY pyproject.toml ./
COPY Makefile ./

# Python dependencies will be installed via postCreateCommand
# to allow mounting the workspace with local modifications



