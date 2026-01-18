#!/bin/bash
set -e
LOG_FILE="/tmp/post-create.log"
echo "Starting post-create.sh at $(date)" > $LOG_FILE

# Use $HOME instead of ~ for reliability in scripts
HOME_DIR="/home/vscode"

# Fix SSH permissions for bind-mounted .ssh directory
if [ -d "$HOME_DIR/.ssh" ]; then
    echo "SSH directory found. Fixing permissions..." >> $LOG_FILE
    
    # Create local ssh config directory
    mkdir -p "$HOME_DIR/.ssh_local"
    
    if [ -f "$HOME_DIR/.ssh/config" ]; then
        echo "Found SSH config. Copying to local..." >> $LOG_FILE
        cp "$HOME_DIR/.ssh/config" "$HOME_DIR/.ssh_local/config"
        chmod 600 "$HOME_DIR/.ssh_local/config"
        
        SSH_CMD="ssh -F $HOME_DIR/.ssh_local/config"
        GIT_EXPORT="export GIT_SSH_COMMAND=\"$SSH_CMD\""
        SSH_ALIAS="alias ssh=\"$SSH_CMD\""
        
        # Add to .zshrc if not already present
        if ! grep -q "GIT_SSH_COMMAND" "$HOME_DIR/.zshrc" 2>/dev/null; then
            echo "Adding GIT_SSH_COMMAND and alias to .zshrc" >> $LOG_FILE
            echo "" >> "$HOME_DIR/.zshrc"
            echo "# Added by post-create.sh" >> "$HOME_DIR/.zshrc"
            echo "$GIT_EXPORT" >> "$HOME_DIR/.zshrc"
            echo "$SSH_ALIAS" >> "$HOME_DIR/.zshrc"
        fi
        
        # Add to .bashrc if not already present
        if ! grep -q "GIT_SSH_COMMAND" "$HOME_DIR/.bashrc" 2>/dev/null; then
            echo "Adding GIT_SSH_COMMAND and alias to .bashrc" >> $LOG_FILE
            echo "$GIT_EXPORT" >> "$HOME_DIR/.bashrc"
            echo "$SSH_ALIAS" >> "$HOME_DIR/.bashrc"
        fi
    else
        echo "No SSH config found in $HOME_DIR/.ssh" >> $LOG_FILE
    fi
    
    # Keys themselves might have bad permissions if they are bind-mounted
    # Note: chmod might fail on a read-only bind mount, so we ignore errors
    echo "Attempting to fix key permissions..." >> $LOG_FILE
    find "$HOME_DIR/.ssh" -type f -name "id_*" -exec chmod 600 {} + 2>/dev/null || true
else
    echo "SSH directory $HOME_DIR/.ssh not found." >> $LOG_FILE
fi

# Fix permissions on .pixi directory (in case it's a mounted volume)
if [ -d ".pixi" ]; then
    echo "Fixing permissions on .pixi directory..." >> $LOG_FILE
    sudo chown -R vscode:vscode .pixi || true
fi

# Fix permissions on .local subdirectories surgicaly
# We avoid recursive chown on the whole .local to prevent host-side permission issues
if [ -d "$HOME_DIR/.local" ]; then
    echo "Ensuring surgical permissions for .local subdirectories..." >> $LOG_FILE
    sudo mkdir -p "$HOME_DIR/.local/state" "$HOME_DIR/.local/share/opencode"
    sudo chown -R vscode:vscode "$HOME_DIR/.local/state" "$HOME_DIR/.local/share/opencode" || true
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