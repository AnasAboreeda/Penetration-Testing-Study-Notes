# [Program Name]

## Program Info

- Program [Link](https://hackerone.com/TARGET)

## In Scope

- link1
- link2
- link2

## Excluded URLs

- link1
- link2

## Program Notes

- note1
- Please limit any automated scanning to XXX requests per second.
- HEADER: X-HackerOne-Research: <YOUR-USERNAME>

## ASNs & IPs

- Visit [bgp.he.net](https://bgp.he.net/search?search%5Bsearch%5D=[TARGET]&commit=Search)

## Result

- AS000000
- AS000000

## IPs

- 0.0.0.0

## Usage

```bash

amass intel -asn 9084,6195 -o asn.txt
```

## Acquisitions

- Visit [crunch base](https://www.crunchbase.com/)

## Acquisitions Result

## [TARGET Acquisition 1](https://www.crunchbase.com/organization/)

## Linked Discovery

- Visit [builtwith](https://builtwith.com/relationships/TARGET)
- Try to enrich the root domains the found relationships

## Reverse WhoIs

- Visit [whoxy](https://www.whoxy.com/TARGET)

## Subdomain Enumeration

```bash
TARGET=$1
mkdir -p output && cd output
mkdir -p subdomain_raw && cd subdomain_raw

# Run the tools and save their outputs
findomain -t $TARGET -q > subdomains_1.txt
subfinder -d $TARGET -o subdomains_2.txt
sublist3r -d $TARGET -t 3 -n -o subdomains_3.txt
gobuster vhost --no-color --append-domain -q -t 50 -u http://$TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o raw_subdomains_4.txt
grep -oE 'Found: [^ ]+' raw_subdomains_4.txt | awk '{print $2}' > subdomains_4.txt

# Combine, sort, and filter unique subdomains
cat subdomains*.txt | sort -t '.' -k2,2 -k1,1 | uniq > subdomains.txt

# Count the unique subdomains
cat subdomains.txt | wc -l
```

## Subdomain Takeover

```bash
subzy run --targets subdomains.txt --timeout 20 --output subdomain_subzy.txt
```

## Get Live Domains

```bash
~/go/bin/httpx -l subdomains.txt -o subdomains-live.txt

cat subdomains-live.txt | wc -l
```

## Get Screenshots of the Live Subdomains

```bash
eyewitness -f subdomains-live.txt --web -d screenshots --timeout 100 --delay 10 --proxy-ip 127.0.0.1 --proxy-port 8080
```

## Port Scanning

```bash
naabu -iL subdomains-live.txt -silent -exclude-cdn -top-ports 1000 -o ports.txt
```

## Get Broken Social Links

```bash
socialhunter -f subdomains-live.txt -w 10 > sociallinks-hunting.txt

cat sociallinks-hunting.txt| grep -i possible
```

## Intersting URLs

## URL 1

## Important Questions

1. How does the app pass data?
   1. resource?parameter=value&parameter2=value2
   2. Method /route/resource/subresource/parameter
2. How/Where does the app talk about the users? understand how are the users referenced in the app and where
   1. where?
      1. cookies
      2. API Calls
      3. Headers
   2. How?
      1. UID
      2. UUID
      3. email
      4. username
3. Does the site have multi-tenancy or user levels?
   1. admin
   2. user
   3. guest
4. Does the site has a unique threat model?
   1. Is it a bank, hospital, streaming service, …?
   2. You need to test for special api keys, tokens, …
5. Has there past security research and vuln?
   1. check hackerone, bugcrowd, …
6. How the app handles these:
   1. XSS
   2. CSRF
   3. Code Injection (SQLi,Template, RCE, noSQL, …)

## App Recon and Analysis

- [ ] Map visible content (Manually)
- [ ] Discover hidden & default content (Direcory/File Bruteforce)
- [ ] Test for debug parameters
- [ ] Identify data entry points (Discover Dynamic Content in Burp Pro)
- [ ] Identify the technologies used (Wapplyzer or similiar)
- [ ] Research existing vulnerabilitties in technology (Google ++)
- [ ] Gather wordlists for specific techniology (Assetnote ones are excellent)
- [ ] Map the attack surface automatically (Spider)
- [ ] Identify all javascript files for later analysis (in your proxy)

## Test Handling of Access

## - [ ] Authentication

- [ ] Test password quality rules
- [ ] Test for username enumeration
- [ ] Test resilience to password guessing
- [ ] Test any account recovery function
- [ ] Test any "remember me" function
- [ ] Test any impersonation function
- [ ] Test username uniqueness
- [ ] Check for unsafe distribution of credentials
- [ ] Test for fail-open conditions
- [ ] Test any multi-stage mechanisms

## - [ ] Session Handling

- [ ] Test tokens for meaning
- [ ] Test tokens for predictability
- [ ] Check for insecure transmission of tokens
- [ ] Check for disclosure of tokens in logs
- [ ] Check mapping of tokens to sessions
- [ ] Check session termination
- [ ] Check for session fixation
- [ ] Check for cross-site request forgery
- [ ] Check cookie scope

## - [ ] Access Controls

- [ ] Understand the access control requirements
- [ ] Test effectiveness of controls, using multiple accounts if possible
- [ ] Test for insecure access control methods (request parameters, Referer header, etc)

## Test Handling of Input

- [ ] Fuzz all request parameters
- [ ] Test for SQL injection
- [ ] Identify all reflected data
- [ ] Test for reflected XSS
- [ ] Test for HTTP header injection
- [ ] Test for arbitrary redirection
- [ ] Test for stored attacks
- [ ] Test for OS command injection
- [ ] Test for path traversal
- [ ] Test for script injection
- [ ] Test for file inclusion
- [ ] Test for SMTP injection
- [ ] Test for native software flaws (buffer overflow, integer bugs, format strings)
- [ ] Test for SOAP injection
- [ ] Test for LDAP injection
- [ ] Test for XPath injection
- [ ] Test for SSRF and HTTP Redirrects in all redirecting parameters

## Test Application Logic

- [ ] Identify the logic attack surface
- [ ] Test transmission of data via the client
- [ ] Test for reliance on client-side input validation
- [ ] Test any thick-client components (Java, ActiveX, Flash)
- [ ] Test multi-stage processes for logic flaws
- [ ] Test handling of incomplete input
- [ ] Test trust boundaries
- [ ] Test transaction logic

## Assess Application Hosting

- [ ] Test segregation in shared infrastructures
- [ ] Test segregation between ASP-hosted applications
- [ ] Test for web server vulnerabilities
- [ ] Default credentials
- [ ] Default content
- [ ] Dangerous HTTP methods
- [ ] Proxy functionality
- [ ] Virtual hosting mis-configuration
- [ ] Bugs in web server software

## Miscellaneous Tests

- [ ] Check for DOM-based attacks
- [ ] Check for frame injection
- [ ] Check for local privacy vulnerabilities
- [ ] Persistent cookies
- [ ] Caching
- [ ] Sensitive data in URL parameters
- [ ] Forms with autocomplete enabled
- [ ] Follow up any information leakage
- [ ] Check for weak SSL ciphers

## URL 2

## URL 3
