# Kali After Setup

## Disable Sleep from Power Manager

- Open Power Manager and disable sleep.

## Install Firefox Addons

- Install [Wappalyzer](https://addons.mozilla.org/nl/firefox/addon/wappalyzer/)
- Install [BuiltWith](https://addons.mozilla.org/en-US/firefox/addon/builtwith/)
- Install [Foxy Proxy](https://addons.mozilla.org/nl/firefox/addon/foxyproxy-standard/)
- Install [User-Agent Switcher and Manager](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/)

## Install Go

- Download and install Go programming language.

```bash
# Download Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# Extract and install Go
tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add Go to the PATH
export PATH=$PATH:/usr/local/go/bin
```

## Prepare the Environment

- Create a directory for tools and set up pimpmykali.

```bash
# Create the tools directory
mkdir ~/tools
cd ~/tools

# Clone the pimpmykali repository
git clone https://github.com/Dewalt-arch/pimpmykali.git
cd pimpmykali

# Make pimpmykali.sh executable
chmod +x pimpmykali.sh

# Run pimpmykali.sh
./pimpmykali.sh
```

## Configure TMUX

## Install Findomain

- Download and install Findomain.

```bash
# Download Findomain
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip

# Unzip and make it executable
unzip findomain-linux.zip
chmod +x findomain

# Move Findomain to /usr/bin
sudo mv findomain /usr/bin/findomain

# Verify installation
findomain --help
```

## Install Legion

- Download and set up the Legion tool.

```bash
# Clone the Legion repository
git clone https://github.com/carlospolop/legion.git /opt/legion
cd /opt/legion/git

# Run the installation script
./install.sh

# Create a symlink to legion.py
ln -s /opt/legion/legion.py /usr/bin/legion
```

## Install Additional Tools

- Install various command-line tools and utilities.

```bash
# Install gau and subjs
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/lc/subjs@latest
go install github.com/utkusen/socialhunter@latest

# Clone fuzzing templates repository
git clone https://github.com/projectdiscovery/fuzzing-templates.git

# Install Katana, Naabu, Subzy, Subjack, Gofinder, Getallurls, Waybackurls, Waybackrobots, and jq
apt install getallurls -y
apt install jq -y

go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/LukaSikic/subzy@latest
go install github.com/haccer/subjack@latest
go install github.com/kkirsche/gofinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/vodafon/waybackrobots@latest
```
