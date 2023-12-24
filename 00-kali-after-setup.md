# Kali After Setup

- Disable sleep from `Power Manager`

## Install Firefox Addons

- Install [Wapalyzer](<[https://addons.mozilla.org/nl/firefox/addon/wappalyzer/](https://addons.mozilla.org/nl/firefox/addon/wappalyzer/)>)
- Install Built with [https://addons.mozilla.org/en-US/firefox/addon/builtwith/](https://addons.mozilla.org/en-US/firefox/addon/builtwith/)
- Install Foxy Proxy [https://addons.mozilla.org/nl/firefox/addon/foxyproxy-standard/](https://addons.mozilla.org/nl/firefox/addon/foxyproxy-standard/)
- Install User-Agent Switcher and Manager [https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/)

```bash
mkdir ~/tools
cd ~/tools

git clone https://github.com/Dewalt-arch/pimpmykali.git
cd pimpmykali
chmod +x pimpmykali.sh
./pimpmykali.sh
```

- Configure TMUX

- Install findomain

```bash
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/findomain
findomain --help
```

- Install legion

```bash
git clone https://github.com/carlospolop/legion.git /opt/legion
cd /opt/legion/git
./install.sh
ln -s /opt/legion/legion.py /usr/bin/legion
```

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/lc/subjs@latest

https://github.com/0xbharath/slurp/releases

go install github.com/utkusen/socialhunter@latest

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# check fuzzing templates
git clone https://github.com/projectdiscovery/fuzzing-templates.git

go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

go install -v github.com/LukaSikic/subzy@lates
go install github.com/haccer/subjack@latest
go install -v github.com/kkirsche/gofinder@latest
apt install getallurls -y
go install github.com/tomnomnom/waybackurls@latest
go install github.com/vodafon/waybackrobots@latest
apt install jq -y
go install -v github.com/LukaSikic/subzy@latest
go install github.com/haccer/subjack@latest 
```