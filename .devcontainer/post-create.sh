#!/bin/bash
set -e
echo "Running post-create.sh at $(date)" >> /tmp/post-create.log

# Source profile to ensure PATH includes npm and other tools
if [ -f ~/.bashrc ]; then
    source ~/.bashrc
fi

# Fix SSH permissions for bind-mounted .ssh directory
if [ -d "~/.ssh" ]; then
    echo "Fixing SSH permissions..."
    # SSH is picky about permissions on config files. 
    # Since ~/.ssh/config is a bind mount, we copy it to a local file with correct perms.
    mkdir -p ~/.ssh_local
    if [ -f ~/.ssh/config ]; then
        cp ~/.ssh/config ~/.ssh_local/config
        chmod 600 ~/.ssh_local/config
        # Tell SSH to use this config for all git operations
        export GIT_SSH_COMMAND="ssh -F /home/vscode/.ssh_local/config"
        echo 'export GIT_SSH_COMMAND="ssh -F /home/vscode/.ssh_local/config"' >> ~/.zshrc
        echo 'export GIT_SSH_COMMAND="ssh -F /home/vscode/.ssh_local/config"' >> ~/.bashrc
    fi
    
    # Ensure keys have correct permissions (SSH will also complain if these are too open)
    find ~/.ssh -type f -name "id_*" -exec chmod 600 {} + 2>/dev/null || true
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
