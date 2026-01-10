# Use the same base image
FROM mcr.microsoft.com/devcontainers/base:ubuntu

# The base image already has a 'vscode' user.
# We want to ensure zsh is installed and set as the default shell.
RUN apt-get update && apt-get install -y zsh curl \
    && chsh -s /usr/bin/zsh vscode \
    && chsh -s /usr/bin/zsh root \
    && git config --system --add safe.directory '*'

# Switch to the vscode user
USER vscode

# Install Pixi
RUN curl -fsSL https://pixi.sh/install.sh | bash
ENV PATH="/home/vscode/.pixi/bin:$PATH"

ENV SHELL=/usr/bin/zsh
