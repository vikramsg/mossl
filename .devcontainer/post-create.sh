#!/bin/bash
set -e
LOG_FILE="/tmp/post-create.log"
echo "Starting post-create.sh at $(date)" > $LOG_FILE

HOME_DIR="/home/vscode"

# 1. Stage .zshrc (Isolation)
if [ -f "$HOME_DIR/.zshrc_host" ]; then
    echo "Staging .zshrc..." >> $LOG_FILE
    cp "$HOME_DIR/.zshrc_host" "$HOME_DIR/.zshrc"
    chmod 644 "$HOME_DIR/.zshrc"
fi

# 2. Stage .ssh and implement Alias Fix
if [ -d "$HOME_DIR/.ssh_host" ]; then
    echo "Staging .ssh directory and setting up alias..." >> $LOG_FILE
    mkdir -p "$HOME_DIR/.ssh_local"
    # Copy from host mount to container local storage
    sudo cp -r "$HOME_DIR/.ssh_host/." "$HOME_DIR/.ssh_local/"
    sudo chown -R vscode:vscode "$HOME_DIR/.ssh_local"
    
    chmod 700 "$HOME_DIR/.ssh_local"
    find "$HOME_DIR/.ssh_local" -type f -exec chmod 600 {} +
    find "$HOME_DIR/.ssh_local" -type f -name "*.pub" -exec chmod 644 {} +
    [ -f "$HOME_DIR/.ssh_local/known_hosts" ] && chmod 644 "$HOME_DIR/.ssh_local/known_hosts"
    
    # Clean host-specific includes (Colima, etc)
    if [ -f "$HOME_DIR/.ssh_local/config" ]; then
        sed -i '/Include .*.colima.ssh_config/d' "$HOME_DIR/.ssh_local/config"
    fi

    # ADD ALIAS AND GIT COMMAND TO LOCAL ZSHRC
    echo "" >> "$HOME_DIR/.zshrc"
    echo "# Container SSH Isolation" >> "$HOME_DIR/.zshrc"
    echo "alias ssh='ssh -F $HOME_DIR/.ssh_local/config'" >> "$HOME_DIR/.zshrc"
    echo "export GIT_SSH_COMMAND=\"ssh -F $HOME_DIR/.ssh_local/config\"" >> "$HOME_DIR/.zshrc"
fi

# 3. Stage Opencode credentials
echo "Setting up opencode credentials..." >> $LOG_FILE
mkdir -p "$HOME_DIR/.local/share/opencode"
if [ -f "$HOME_DIR/.opencode_staging/auth.json" ]; then
    cp "$HOME_DIR/.opencode_staging/auth.json" "$HOME_DIR/.local/share/opencode/auth.json"
    chmod 600 "$HOME_DIR/.local/share/opencode/auth.json"
    echo "opencode auth.json copied." >> $LOG_FILE
fi

# 4. Standard Installs
[ -d ".pixi" ] && sudo chown -R vscode:vscode .pixi || true
echo "Running pixi install..." >> $LOG_FILE
pixi install >> $LOG_FILE 2>&1

if command -v npm &> /dev/null; then
    echo "Installing global node tools..." >> $LOG_FILE
    npm install -g @google/gemini-cli @openai/codex opencode-ai >> $LOG_FILE 2>&1
fi

echo "post-create.sh finished at $(date)" >> $LOG_FILE
