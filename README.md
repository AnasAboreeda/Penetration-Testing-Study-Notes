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
    - [Content Discovery](#content-discovery)
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
  - [Online Tools](#online-tools)

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

### Content Discovery

- Run this script [content-discovery.sh](./scripts/content-discovery.sh)

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

## Online Tools

- [CrackStation](https://crackstation.net/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [DNSDumpster](https://dnsdumpster.com/)
