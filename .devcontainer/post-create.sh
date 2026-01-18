#!/bin/bash
set -e
LOG_FILE="/tmp/post-create.log"
echo "Starting post-create.sh at $(date)" > $LOG_FILE

# Use $HOME instead of ~ for reliability in scripts
HOME_DIR="/home/vscode"

# Surgical setup for .zshrc to avoid host-container mismatch
if [ -f "$HOME_DIR/.zshrc_host" ]; then
    echo "Staging .zshrc from host..." >> $LOG_FILE
    cp "$HOME_DIR/.zshrc_host" "$HOME_DIR/.zshrc"
    chmod 644 "$HOME_DIR/.zshrc"
else
    echo "No host .zshrc found at $HOME_DIR/.zshrc_host" >> $LOG_FILE
fi

# Surgical setup for .ssh to avoid UID/GID permission issues
if [ -d "$HOME_DIR/.ssh_host" ]; then
    echo "Staging .ssh directory from host..." >> $LOG_FILE
    mkdir -p "$HOME_DIR/.ssh"
    cp -r "$HOME_DIR/.ssh_host/." "$HOME_DIR/.ssh/"
    
    # Fix permissions surgically for the container user
    chmod 700 "$HOME_DIR/.ssh"
    find "$HOME_DIR/.ssh" -type f -exec chmod 600 {} +
    find "$HOME_DIR/.ssh" -type f -name "*.pub" -exec chmod 644 {} +
    [ -f "$HOME_DIR/.ssh/known_hosts" ] && chmod 644 "$HOME_DIR/.ssh/known_hosts"
    
    # Clean up any host-specific Include directives that might fail in container
    if [ -f "$HOME_DIR/.ssh/config" ]; then
        sed -i '/Include .*.colima.ssh_config/d' "$HOME_DIR/.ssh/config"
    fi
    echo ".ssh directory staged and permissions fixed." >> $LOG_FILE
else
    echo "No host .ssh found at $HOME_DIR/.ssh_host" >> $LOG_FILE
fi

# Fix permissions on .pixi directory (in case it's a mounted volume)
if [ -d ".pixi" ]; then
    echo "Fixing permissions on .pixi directory..." >> $LOG_FILE
    sudo chown -R vscode:vscode .pixi || true
fi

# Install pixi dependencies
echo "Running pixi install..." >> $LOG_FILE
pixi install >> $LOG_FILE 2>&1

# Surgical credential setup for opencode
echo "Setting up opencode credentials..." >> $LOG_FILE
mkdir -p "$HOME_DIR/.local/share/opencode"
if [ -f "$HOME_DIR/.opencode_staging/auth.json" ]; then
    cp "$HOME_DIR/.opencode_staging/auth.json" "$HOME_DIR/.local/share/opencode/auth.json"
    chmod 600 "$HOME_DIR/.local/share/opencode/auth.json"
    echo "opencode auth.json copied and secured." >> $LOG_FILE
else
    echo "Warning: Staged auth.json not found." >> $LOG_FILE
fi

if command -v npm &> /dev/null; then
    echo "Installing Gemini CLI and opencode..." >> $LOG_FILE
    npm install -g @google/gemini-cli @openai/codex opencode-ai >> $LOG_FILE 2>&1
else
    echo "Warning: npm not found." >> $LOG_FILE
fi

echo "post-create.sh finished at $(date)" >> $LOG_FILE
