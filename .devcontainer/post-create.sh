#!/bin/bash
set -e
echo "Running post-create.sh at $(date)" >> /tmp/post-create.log

# Source profile to ensure PATH includes npm and other tools
if [ -f ~/.bashrc ]; then
    source ~/.bashrc
fi

# Fix permissions on .pixi directory (in case it's a mounted volume)
if [ -d ".pixi" ]; then
    echo "Fixing permissions on .pixi directory..."
    sudo chown -R "$(id -u):$(id -g)" .pixi
fi

# Install pixi dependencies
pixi install

# Ensure npm prefix is unset to avoid nvm conflicts
if [ -f ~/.npmrc ]; then
    echo "Cleaning ~/.npmrc..."
    sed -i '/prefix=/d' ~/.npmrc
    sed -i '/globalconfig=/d' ~/.npmrc
fi

if command -v npm &> /dev/null; then
    # Install Coding CLI
    echo "Installing Gemini CLI..."
    npm install -g @google/gemini-cli @openai/codex
else
    echo "Warning: npm not found. Skipping Coding CLI installation."
fi
