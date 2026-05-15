FROM python:3.13-slim

# UID/GID de l'utilisateur local (passés au build) pour matcher les permissions du montage
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# Install required system dependencies (dev tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    openssh-client \
    gnupg \
    build-essential \
    ca-certificates \
    curl \
    wget \
    vim \
    nano \
    php8.4-cli \
    php8.4-xml \
    sslscan \
    xz-utils \
    bzip2 \
    && apt-get clean -yq \
    && apt-get autoremove -yq \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Update pip and install Playwright (same base as Dockerfile.headless)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir playwright

# Playwright system deps + Firefox (same as Dockerfile.headless, tout dans l’image)
RUN apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests xz-utils curl bzip2 \
    && playwright install-deps firefox \
    && playwright install firefox \
    && apt-get clean -yq \
    && apt-get autoremove -yq \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /workspace

# Copy project configuration files
COPY pyproject.toml ./
COPY Makefile ./

# Utilisateur avec UID/GID de l'hôte (évite soucis de permissions sur les fichiers montés)
RUN export uid=${USER_UID:-1000} gid=${USER_GID:-1000} \
    && (groupadd --gid $gid wapiti 2>/dev/null || true) \
    && useradd --uid $uid --gid $gid -m -s /bin/bash wapiti \
    && apt-get update && apt-get install -y --no-install-recommends sudo \
    && echo "wapiti ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && apt-get clean -yq && rm -rf /var/lib/apt/lists/*

USER wapiti
WORKDIR /workspace

# Scripts pip (wapiti, wapiti-getcookie, …) installés en ~/.local/bin par postCreate
ENV PATH="/home/wapiti/.local/bin:$PATH"

# Dépendances Python installées au postCreate (workspace monté)

