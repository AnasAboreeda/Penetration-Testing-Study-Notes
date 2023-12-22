# Subdomain Enumeration

**Domain Reconnaissance Tools**

1. **SSL/TLS Certificate Search**:
   - **[crt.sh](http://crt.sh/)**: A web service for exploring SSL/TLS certificates. [Visit crt.sh](https://crt.sh/)
   - **Entrust Certificate Transparency Search**: A tool to look up SSL/TLS certificates. [Visit Entrust CT Search](https://ui.ctsearch.entrust.com/ui/ctsearchui)
2. **Subdomain Enumeration Tools**:
   - **Google Dorking**:
     - Using `site:*.tryhackme.com` to find subdomains related to `tryhackme.com`.
   - **dnsrecon**:
     - Command: `dnsrecon -t brt -d mydomain.com` for brute-forcing subdomains.
   - **sublist3r**:
     - A tool for automated subdomain discovery. [GitHub Repository](https://github.com/aboul3la/Sublist3r)
   - **ffuf (Fuzz Faster U Fool)**:
     - Basic command: `ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u <http://10.10.186.190`>
     - Enhanced with output filtering: `ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u <http://10.10.186.190> -fs {size}`
3. **Additional Subdomain Discovery Tools**:
   - **subfinder**: [GitHub Repository](https://github.com/projectdiscovery/subfinder)
   - **Amass**: [GitHub Repository](https://github.com/owasp-amass/amass)
   - **aquatone**: [GitHub Repository](https://github.com/michenriksen/aquatone)
   - **knock**: [GitHub Repository](https://github.com/guelfoweb/knock)
   - **Findomain**: Noted as the fastest tool. [GitHub Repository](https://github.com/Findomain/Findomain)

**Manual Subdomain Enumeration**

- Utilize services like **[crt.sh](http://crt.sh/)**, **Censys** ([search.censys.io](https://search.censys.io/)), and **Shodan** ([shodan.io](http://shodan.io/)) for manual subdomain discovery.

**Automated Application Commands**

- **findomain**: `findomain -t miro.com -q > subdomains.txt`
- **subfinder (Recursive)**: `subfinder -d nahamstore.com -o passive2.txt -all`

**Resources for Subdomain Takeover**

- [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)
- [Can I Take Over XYZ V2](https://github.com/shifa123/Can-I-take-over-xyz-v2)

**AWS Subdomain Takeover Steps**

1. Check for "bucket does not exist" messages on the subdomain.
2. Determine the original bucket's region.
3. Create a new bucket in the same region with the subdomain's name.
4. Upload and set 'index.html' to public access.
5. Configure the bucket for static file hosting.

**Automating Subdomain Takeover**

```bash
subzy run --targets subdomains.txt --timeout 20 --output subdomain_subzy.txt
subjack -w subdomains.txt -t 100 -timeout 30 -o subdomain_subjack.txt -ssl
```
