# Pentesting - Everything, Everywhere, All In One Place

This is a collection of all the commands and tools I use for pentesting. I will try to keep it updated as much as possible.

If you liked the old content, you can find it in the [archive](archive) folder.

## Bug Hunting Roadmap

- [ ] Grab all the in-scope urls
- [ ] Subdomain enumeration for everyone of them
- [ ] Get live subdomains
- [ ] Check for subdomain takeover
- [ ] Screenshot all the live domains
- [ ] Network
  - [ ] Open Ports / Services
- [ ] Content Discovery
  - [ ] Framework
  - [ ] Favicon
  - [ ] Directories
  - [ ] URLs
  - [ ] S3 Buckets
  - [ ] JS files
  - [ ] Broken Social Links
  - [ ] GIT Repositories
- [ ] Vulnerability Scanning
  - [ ] XSS Scanning
  - [ ] SQL Injection
  - [ ] XXE Injection
  - [ ] SSRF Injection
  - [ ] Race Condition Testing
  - [ ] CORS Vulnerability Testing
  - [ ] Parameter Tampering
  - [ ] Local File Inclusion / Directory Traversal
  - [ ] IDOR

## Table of Contents

- [Pentesting - Everything, Everywhere, All In One Place](#pentesting---everything-everywhere-all-in-one-place)
  - [Bug Hunting Roadmap](#bug-hunting-roadmap)
  - [Table of Contents](#table-of-contents)
  - [Preparation](#preparation)
  - [Reconnaissance](#reconnaissance)
    - [Subdomain Enumeration](#subdomain-enumeration)
    - [Get live subdomains](#get-live-subdomains)
    - [Subdomain Takeover](#subdomain-takeover)
    - [Get Screenshots of the live subdomians](#get-screenshots-of-the-live-subdomians)
    - [Port Scanning](#port-scanning)
    - [Content Discovery](#content-discovery)
      - [Content Discovery Lists](#content-discovery-lists)
    - [Questions to ask yourself when doing content discovery](#questions-to-ask-yourself-when-doing-content-discovery)
    - [Heat Mapping / Content Discovery](#heat-mapping--content-discovery)
    - [Parameter Analysis](#parameter-analysis)
    - [Get S3 buckets](#get-s3-buckets)
    - [Add all live domains to burpsuite](#add-all-live-domains-to-burpsuite)
    - [Get IPs, PORTS, and Services](#get-ips-ports-and-services)
    - [Get Broken social links](#get-broken-social-links)
  - [Vulnerabilities Scanning](#vulnerabilities-scanning)
    - [XSS Scanning](#xss-scanning)
    - [SQL Injection](#sql-injection)
    - [XXE Injection](#xxe-injection)
    - [SSRF Injection](#ssrf-injection)
    - [Git Repository Scanning](#git-repository-scanning)
    - [Race Condition Testing](#race-condition-testing)
    - [CORS Vulnerability Testing](#cors-vulnerability-testing)
    - [Parameter Tampering](#parameter-tampering)
    - [Local File Inclusion / Directory Traversal](#local-file-inclusion--directory-traversal)
    - [IDOR](#idor)
  - [Tips and Tricks](#tips-and-tricks)
    - [Start a local server to serve local files in a directory](#start-a-local-server-to-serve-local-files-in-a-directory)
    - [Listen to a local port](#listen-to-a-local-port)
  - [Online Tools](#online-tools)
  - [References](#references)

## Preparation

```bash
export TARGET="target.com"
mkdir $TARGET
cd $TARGET
mkdir screenshots
export VT_APIKEY=<YourAPIKEY>
```

## Reconnaissance

### Subdomain Enumeration

```bash

subfinder -d $TARGET -o subdomains_1.txt

findomain -t $TARGET -q > subdomains_2.txt

sublist3r -d $TARGET -t 3 -n -o subdomains_3.txt

gobuster vhost --no-color --append-domain -q -t 50 -u http://$TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o raw_subdomains_4.txt

grep -oE 'Found: [^ ]+' raw_subdomains_4.txt | awk '{print $2}' > subdomains_4.txt

cat subdomains*.txt | sort | uniq > subdomains.txt

cat subdomains.txt| wc -l

# Go to
# https://chaos.projectdiscovery.io/#/
# to get all the subdomains for a program

## Check https://dnsdumpster.com/ it has nice graph
```

### Get live subdomains

```bash
~/go/bin/httpx -l subdomains.txt -o subdomains-live.txt

cat subdomains-live.txt | wc -l
```

### Subdomain Takeover

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

### Get Screenshots of the live subdomians

```bash
eyewitness -f subdomains-live.txt --web -d screenshots --timeout 100 --delay 10 --proxy-ip 127.0.0.1 --proxy-port 8080

# or

cat subdomains-live.txt | aquatone --out screenshots -scan-timeout 900 -chrome-path /usr/bin/chromium
```

### Port Scanning

```bash
naabu -iL subdomains-live.txt -silent -exclude-cdn -top-ports 1000 -o ports.txt
```

### Content Discovery

1. Based on Tech
2. COTS / PAID / OSS
3. Custom
4. Historical
5. Recursive
6. Mobile APIs
7. Change Detection

#### Content Discovery Lists

- Download the lists from [here](https://wordlists-cdn.assetnote.io/data/)

`wget -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/ -nH -e robots=off`

1. Tech
   1. IIS / MSF
      1. assetnote/httparchive*aspx_asp_cfm_svc_ashx_asmx*
      2. IIS Shortname Scanner
   2. PHP + CGI
      1. assetnote/httparchive_cgi_pl
      2. assetnote/httparchive_php
   3. General API
      1. assetnote/httparchive*apiroutes*
      2. assetnote/swagger-wordlist
      3. seclists/Discovery/Web-Content/api/api-endpoints.txt
   4. Java
      1. assetnote/httparchive_jsp_jspa_do_action
   5. Generic
      1. assetnote/httparchive*directories_1m*
      2. RAFT
      3. Robots Disallowed
      4. github.com/six2dez/OneListForAll
      5. jhadix/content_discovery_all.txt
   6. Other
      1. Use Technology <=> Host Mappings from [assetnote.io](https://wordlists.assetnote.io/)
         - adobe_experience_manager <=> assetnote/httparchive_adobe_experience_manager
         - apache <=> assetnote/httparchive_apache
         - cherrypy <=> assetnote/httparchive_cherrypy
         - coldfusion <=> assetnote/httparchive_coldfusion
         - django <=> assetnote/httparchive_django
         - express <=> assetnote/httparchive_express
         - flask <=> assetnote/httparchive_flask
         - laravel <=> assetnote/httparchive_laravel
         - nginx <=> assetnote/httparchive_nginx
         - rails <=> assetnote/httparchive_rails
         - spring <=> assetnote/httparchive_spring
         - symfony <=> assetnote/httparchive_symfony
         - tomcat <=> assetnote/httparchive_tomcat
         - yii <=> assetnote/httparchive_yii
         - zend <=> assetnote/httparchive_zend
2. OSS (Open Source Software) / PAID / COTS (Commercial Off The Shelf)
   1. If the app is open source, you can use the source code to find endpoints
      1. You can use [Source2URL](https://github.com/danielmiessler/Source2URL/blob/master/Source2URL)
   2. PAID / COTS (Commercial Off The Shelf)
      1. Download a Demo version of the software
3. Custom
   1. use [Scavneger](https://github.com/0xDexter0us/Scavenger) to generate custom wordlists from burp history
4. Historical
   1. `echo bugcrowd.com | gau | wordlistgen | sort -u > wordlist.txt`
5. Recursive
   1. Do recursion on 401 and 403 pages, and then do content discovery on the new pages
6. Mobile APIs
   1. Scan APK file for URIs, endpoints & secrets. [apkleaks](https://github.com/dwisiswant0/apkleaks)
7. Change Detection
   1. subscribe to the newsletter of the target
   2. conferences / events / webinars from the targets
   3. Monitor the target's social media accounts
   4. [change detection](https://changedetection.io/)

### Questions to ask yourself when doing content discovery

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
   1. Is it a bank, hospital, streaming service, ...?
   2. You need to test for special api keys, tokens, ...
5. Has there past security research and vuln?
   1. check hackerone, bugcrowd, ...
6. How the app handles these:
   1. XSS
   2. CSRF
   3. Code Injection (SQLi,Template, RCE, noSQL, ...)

- Spider using Burp Suite or OWASP ZAP or [Hakrawler](https://github.com/hakluke/hakrawler) or [Gospider](https://github.com/jaeles-project/gospider)

- Extact links and parse js and spider and inline javascript

  - Using [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder)`xnLinkFinder -i tesla.com -d 2 -sp https://tesla.com -o tesla.txt`
  - Using [GAP](https://github.com/xnl-h4ck3r/GAP-Burp-Extension) Burp Extension

- Check for oudated js libraries using RetireJS in Burp Suite

### Heat Mapping / Content Discovery

1. Upload functions
   1. Integrations (From 3rd party)
      1. XSS
   2. Self Uploads
      1. XML Based (Docs, PDFs, ...)
         1. SSRF, XSS
      2. Image Based (JPG, PNG, ...)
         1. Shell, XSS
            1. Name
            2. Binary Header
            3. Metadata
   3. Where is data stored?
      1. S3 Permissions
2. Content Types
   1. Look for multipart-forms
   2. Look for JSON
   3. Look for XML
3. API
   1. GraphQL
   2. REST / Methods
4. Account Section
   1. Profile
      1. Stored XSS
   2. App Custom Fields
   3. Integrations
      1. SSRF, XSS
5. Errors

### Parameter Analysis

- Use [GF-Patterns](https://github.com/1ndianl33t/Gf-Patterns) to find parameters
- Use [sus_params](https://github.com/g0ldencybersec/sus_params)

- Run this script [content-discovery.sh](./scripts/content-discovery.sh)

`feroxbuster -u http://localhost:3000/#/ --extract-links -o links.txt --filter-status 404 500 --rate-limit 100 --scan-limit 1 -t 10 --random-agent `

- Check favicon, Search here for the md5 to get the framework [OWASP_favicon_database](https://wiki.owasp.org/index.php/OWASP_favicon_database)

```bash
curl $TARGET/favicon.ico | md5sum
```

- Check /robots.txt
- Check /sitemap.xml
- Check HTTP headers
- Use google dorks

  - site: target.com
    - inrul:admin
    - filetype:pdf
    - intitle:admin

- Check https://archive.org/web/
- Check Github / Gitlab / Bitbucket
- Search in target tab in Burp Suite for words like: path, link, ...

### Get S3 buckets

```bash
slurp domain -t booking.com

# TODO: check s3 workflow
# also check this https://github.com/nikhil1232/Bucket-Flaws
```

### Add all live domains to burpsuite

```bash
cat subdomains-live.txt | xargs -P 10 -I {} curl -k -x http://localhost:8080 {} -o /dev/null
```

### Get IPs, PORTS, and Services

- Go to https://www.shodan.io/
  - Search: `org:"TARGET.com"`
  - OR `ssl:"TARGET.com"`

### Get Broken social links

```bash
socialhunter -f subdomains-live.txt -w 10 > sociallinks-hunting.txt
```

## Vulnerabilities Scanning

### XSS Scanning

```bash
# Find XSS vulnerabilities using XSSHunter
xsshunter -u $TARGET
```

### SQL Injection

```bash
# Test for SQL injection vulnerabilities using SQLMap
sqlmap -u $TARGET
```

### XXE Injection

```bash
# Test for XXE vulnerabilities using XXEInjector
xxeinjector $TARGET
```

### SSRF Injection

```bash
# Detect SSRF vulnerabilities using SSRFDetector
ssrfdetector $TARGET
```

### Git Repository Scanning

```bash
# Scan for Git repositories using GitTools
gitdumper $TARGET
```

```bash
# Find secrets in Git repositories using gitallsecrets
gitallsecrets -u $TARGET
```

### Race Condition Testing

```bash
# Test for race conditions using RaceTheWeb
racetheweb $TARGET
```

### CORS Vulnerability Testing

```bash
# Test for CORS vulnerabilities using CORStest
corstest $TARGET
```

### Parameter Tampering

```bash
# Test for parameter tampering vulnerabilities using parameth
parameth -u $TARGET
```

### Local File Inclusion / Directory Traversal

```bash
ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -u http://10.10.41.192/playground.php?file=FUZZ -fr Failed
```

files we are intersted to see

| /etc/issue                  | contains a message or system identification to be printed before the login prompt.                                                                                |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| /etc/profile                | controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
| /proc/version               | specifies the version of the Linux kernel                                                                                                                         |
| /etc/passwd                 | has all registered user that has access to a system                                                                                                               |
| /etc/shadow                 | contains information about the system's users' passwords                                                                                                          |
| /root/.bash_history         | contains the history commands for root user                                                                                                                       |
| /var/log/dmessage           | contains global system messages, including the messages that are logged during system startup                                                                     |
| /var/mail/root              | all emails for root user                                                                                                                                          |
| /root/.ssh/id_rsa           | Private SSH keys for a root or any known valid user on the server                                                                                                 |
| /var/log/apache2/access.log | the accessed requests for Apache  webserver                                                                                                                       |
| C:\boot.ini                 | contains the boot options for computers with BIOS firmware                                                                                                        |

### IDOR

**What is an IDOR?**

IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.

This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects (files, data, documents), too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

- you should check prarameters like `/?userId=123`
  - it can be hashed
  - it can be encoded
  - if it’s unpredictable like uuid, you should create 2 accounts and try to swap their ids and see if you can access each other’s private content like profiles

## Tips and Tricks

### Start a local server to serve local files in a directory

```bash

python3 -m http.server 8000

```

### Listen to a local port

```bash
nc -nlvp 9001
```

## Online Tools

- [CrackStation - Free Password Hash Cracker](https://crackstation.net/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [DNSDumpster](https://dnsdumpster.com/)
- [Reverse Shell Generator](https://www.revshells.com/)

## References

- [Interview Questions](https://tib3rius.com/interview-questions)
- [Security Reference Guide](https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [Awesome Pentest Cheat SheetsW](https://github.com/coreb1t/awesome-pentest-cheat-sheets)
- [Awesome Bugbounty Tools](https://github.com/vavkamil/awesome-bugbounty-tools)
