# ssl.mojo

The objective is to implement enough OpenSSL bindings to allow `HTTPS` connections. 

# Setup

We will use Pixi for all setup requirements. 

## Installation
```
curl -fsSL https://pixi.sh/install.sh | bash
echo 'eval "$(pixi completion --shell zsh)"' >> ~/.zshrc
```

## Usage
```
pixi init
pixi add requests
pixi shell # To got into an activated env
```