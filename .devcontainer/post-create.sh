#!/bin/bash
set -e

# Source profile to ensure PATH includes npm and other tools
if [ -f ~/.bashrc ]; then
    source ~/.bashrc
fi

# Copy SSH keys from mounted location to ~/.ssh with correct ownership and permissions
if [ -d /tmp/host-ssh ] && [ -n "$(ls -A /tmp/host-ssh 2>/dev/null)" ]; then
  # Create .ssh directory with correct ownership
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  
  # Copy all SSH files from mounted location (this creates files with correct ownership)
  cp -r /tmp/host-ssh/* ~/.ssh/ 2>/dev/null || true
  
  # Set correct permissions on all SSH files
  chmod 700 ~/.ssh
  chmod 600 ~/.ssh/id_* ~/.ssh/*.pem 2>/dev/null || true
  chmod 644 ~/.ssh/*.pub 2>/dev/null || true
  [ -f ~/.ssh/config ] && chmod 600 ~/.ssh/config || true
  [ -f ~/.ssh/known_hosts ] && chmod 644 ~/.ssh/known_hosts || true
  [ -f ~/.ssh/known_hosts.old ] && chmod 644 ~/.ssh/known_hosts.old || true
fi

# Install Pixi
if ! command -v pixi &> /dev/null; then
    echo "Installing Pixi..."
    curl -fsSL https://pixi.sh/install.sh | bash
    export PATH="$HOME/.pixi/bin:$PATH"
    echo 'export PATH="$HOME/.pixi/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc
fi

# Fix permissions on .pixi directory (in case it's a mounted volume)
if [ -d ".pixi" ]; then
    echo "Fixing permissions on .pixi directory..."
    sudo chown -R "$(id -u):$(id -g)" .pixi
fi

# Install pixi dependencies
pixi install

# Configure npm to install global packages in user directory (no sudo needed)
if command -v npm &> /dev/null; then
    # Set npm prefix to user directory
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    export PATH=~/.npm-global/bin:$PATH
    echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
    echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.zshrc
    
    # Install Gemini CLI without sudo
    echo "Installing Gemini CLI..."
    npm install -g @google/gemini-cli
else
    echo "Warning: npm not found. Skipping Gemini CLI installation."
fi
