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
        
        # Add to .zshrc if not already present
        if ! grep -q "GIT_SSH_COMMAND" "$HOME_DIR/.zshrc" 2>/dev/null; then
            echo "Adding GIT_SSH_COMMAND to .zshrc" >> $LOG_FILE
            echo "" >> "$HOME_DIR/.zshrc"
            echo "# Added by post-create.sh" >> "$HOME_DIR/.zshrc"
            echo "$GIT_EXPORT" >> "$HOME_DIR/.zshrc"
        fi
        
        # Add to .bashrc if not already present
        if ! grep -q "GIT_SSH_COMMAND" "$HOME_DIR/.bashrc" 2>/dev/null; then
            echo "Adding GIT_SSH_COMMAND to .bashrc" >> $LOG_FILE
            echo "$GIT_EXPORT" >> "$HOME_DIR/.bashrc"
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
    sudo chown -R vscode:vscode .pixi
fi

# Install pixi dependencies
echo "Running pixi install..." >> $LOG_FILE
pixi install >> $LOG_FILE 2>&1

# Ensure npm prefix is unset to avoid nvm conflicts
if [ -f "$HOME_DIR/.npmrc" ]; then
    echo "Cleaning $HOME_DIR/.npmrc..." >> $LOG_FILE
    sed -i '/prefix=/d' "$HOME_DIR/.npmrc"
    sed -i '/globalconfig=/d' "$HOME_DIR/.npmrc"
fi

if command -v npm &> /dev/null; then
    echo "Installing Gemini CLI..." >> $LOG_FILE
    npm install -g @google/gemini-cli @openai/codex >> $LOG_FILE 2>&1
else
    echo "Warning: npm not found." >> $LOG_FILE
fi

echo "post-create.sh finished at $(date)" >> $LOG_FILE