# Pentensting - Everything, Everywhere, All In One Place

This is a collection of all the commands and tools I use for pentesting. I will try to keep it updated as much as possible.

If you liked the old content, you can find it in the [archive](archive) folder.

## Table of Contents

- [Pentensting - Everything, Everywhere, All In One Place](#pentensting---everything-everywhere-all-in-one-place)
  - [Table of Contents](#table-of-contents)
  - [Preparation](#preparation)
  - [Reconnaissance](#reconnaissance)
    - [Subdomain Enumeration](#subdomain-enumeration)
    - [Subdomain Takeover](#subdomain-takeover)
    - [Get alive subdomains](#get-alive-subdomains)
    - [Content Discovery](#content-discovery)
    - [Get Screenshots of the alive subdomians](#get-screenshots-of-the-alive-subdomians)
    - [Add all live domains to burpsuite](#add-all-live-domains-to-burpsuite)
    - [Get IPs, PORTS, and Services](#get-ips-ports-and-services)
    - [Get S3 buckets](#get-s3-buckets)
    - [Get Broken social links](#get-broken-social-links)
  - [Scanning](#scanning)
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

## Preparation

```bash
export TARGET="target.com"
mkdir $TARGET
cd $TARGET
mkdir screenshots
```

## Reconnaissance

### Subdomain Enumeration

```bash

subfinder -d $TARGET -o subdomains_1.txt

findomain -t $TARGET -q > subdomains_2.txt

sublist3r -d $TARGET -t 3 -n -o subdomains_3.txt

gobuster vhost -u $TARGET -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt | grep 200 > subdomains_4.txt

wfuzz -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt --hc 404 --hl 9  -c -t 50 -u $TARGET -H "Host: FUZZ.$TARGET" | grep 200 > subdomains_5.txt

massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S -w resolved.txt subdomains_6.txt

cat subdomains*.txt | sort | uniq > subdomains.txt

cat subdomains.txt| wc -l

# Go to
# https://chaos.projectdiscovery.io/#/
# to get all the subdomains for a program

## Check https://dnsdumpster.com/ it has nice graph
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

### Get alive subdomains

```bash
~/go/bin/httpx -l subdomains.txt -o subdomains-alive.txt

cat subdomains-alive.txt | wc -l
```

### Content Discovery

```bash
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404 --hl 9  -c -t 50 $TARGET/FUZZ | grep 200 > content-discovery.txt

# Extract links using GoLinkFinder
gofinder $TARGET | tee -a content-discovery.txt

# Extract all URLs using getallurls
getallurls $TARGET | tee -a content-discovery.txt

# Extract archived URLs using WayBackUrls
waybackurls $TARGET | tee -a content-discovery.txt

# Extract robots.txt from archived URLs using WayBackRobots
waybackrobots $TARGET | tee -a content-discovery.txt

ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u $TARGET/FUZZ | tee -a content-discovery.txt

dirb $TARGET/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt | tee -a content-discovery.txt

gobuster dir --url $TARGET/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt | tee -a content-discovery.txt
```

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

### Get Screenshots of the alive subdomians

```bash
eyewitness -f subdomains-alive.txt --web -d screenshots --timeout 100 --delay 10 --proxy-ip 127.0.0.1 --proxy-port 8080

# or

cat subdomains-alive.txt | aquatone --out screenshots -scan-timeout 900 -chrome-path /usr/bin/chromium
```

### Add all live domains to burpsuite

```bash
cat subdomains-alive.txt | xargs -P 10 -I {} curl -k -x http://localhost:8080 {} -o /dev/null
```

### Get IPs, PORTS, and Services

- Go to https://www.shodan.io/
  - Search: `org:"TARGET.com"`
  - OR `ssl:"TARGET.com"`

### Get S3 buckets

```bash
slurp domain -t booking.com

# TODO: check s3 workflow
# also check this https://github.com/nikhil1232/Bucket-Flaws
```

### Get Broken social links

```bash
socialhunter -f subdomains-alive.txt -w 10 > sociallinks-hunting.txt
```

## Scanning

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
