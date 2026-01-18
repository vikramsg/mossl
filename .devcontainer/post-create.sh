#!/bin/bash
set -e
LOG_FILE="/tmp/post-create.log"
echo "Starting post-create.sh at $(date)" > $LOG_FILE

HOME_DIR="/home/vscode"

# 1. Stage .zshrc
if [ -f "$HOME_DIR/.zshrc_host" ]; then
    echo "Staging .zshrc..." >> $LOG_FILE
    cp "$HOME_DIR/.zshrc_host" "$HOME_DIR/.zshrc"
    chmod 644 "$HOME_DIR/.zshrc"
fi

# 2. Stage .ssh (Surgical copy to avoid UID/GID issues)
if [ -d "$HOME_DIR/.ssh_host" ]; then
    echo "Staging .ssh..." >> $LOG_FILE
    mkdir -p "$HOME_DIR/.ssh"
    cp -r "$HOME_DIR/.ssh_host/." "$HOME_DIR/.ssh/"
    
    # Permissions for Linux
    chmod 700 "$HOME_DIR/.ssh"
    find "$HOME_DIR/.ssh" -type f -exec chmod 600 {} +
    find "$HOME_DIR/.ssh" -type f -name "*.pub" -exec chmod 644 {} +
    [ -f "$HOME_DIR/.ssh/known_hosts" ] && chmod 644 "$HOME_DIR/.ssh/known_hosts"
    
    # Strip Colima/host-specific includes
    if [ -f "$HOME_DIR/.ssh/config" ]; then
        sed -i '/Include .*.colima.ssh_config/d' "$HOME_DIR/.ssh/config"
    fi

    # Add SSH alias to .zshrc (Requested approach)
    echo "Adding ssh alias to .zshrc..." >> $LOG_FILE
    echo "" >> "$HOME_DIR/.zshrc"
    echo "# Added for devcontainer isolation" >> "$HOME_DIR/.zshrc"
    echo "alias ssh='ssh -F $HOME_DIR/.ssh/config'" >> "$HOME_DIR/.zshrc"
fi

# 3. Opencode Credentials
mkdir -p "$HOME_DIR/.local/share/opencode"
if [ -f "$HOME_DIR/.opencode_staging/auth.json" ]; then
    cp "$HOME_DIR/.opencode_staging/auth.json" "$HOME_DIR/.local/share/opencode/auth.json"
    chmod 600 "$HOME_DIR/.local/share/opencode/auth.json"
fi

# 4. Permissions & Installs
[ -d ".pixi" ] && sudo chown -R vscode:vscode .pixi || true
pixi install >> $LOG_FILE 2>&1

if command -v npm &> /dev/null; then
    npm install -g @google/gemini-cli @openai/codex opencode-ai >> $LOG_FILE 2>&1
fi

echo "post-create.sh finished at $(date)" >> $LOG_FILE
