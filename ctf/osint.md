# OSINT (Open Source Intelligence) - CTF Guide

OSINT involves gathering information from publicly available sources to solve challenges.

## Table of Contents

- [Search Engines](#search-engines)
- [Social Media](#social-media)
- [Domain & IP Intelligence](#domain--ip-intelligence)
- [Image Intelligence](#image-intelligence)
- [People Search](#people-search)
- [Tools](#tools)

## Search Engines

### Google Dorking

```
# Site-specific search
site:example.com "password"
site:example.com filetype:pdf

# Find subdomains
site:*.example.com

# Find specific files
filetype:pdf "confidential"
filetype:xls "email addresses"
filetype:sql "password"

# Find login pages
inurl:admin intitle:login
inurl:wp-login.php

# Find exposed directories
intitle:"index of" "parent directory"

# Find cameras
inurl:view/index.shtml

# Cache and older versions
cache:example.com

# Common patterns
intext:"password" filetype:log
inurl:wp-config.php intext:DB_PASSWORD
```

### Other Search Engines

```bash
# Shodan - IoT/Server search
https://www.shodan.io/
# Search for: org:"Company" port:22

# Censys - Internet-wide scanning
https://censys.io/

# Have I Been Pwned - Breach data
https://haveibeenpwned.com/

# Hudson Rock - Infostealer intelligence
https://www.hudsonrock.com/threat-intelligence-cybercrime-tools

# Intelligence X - OSINT search engine
https://intelx.io/

# Wigle - WiFi networks
https://wigle.net/
```

## Social Media

### Username Enumeration

```bash
# Check username across platforms
# Tool: sherlock
python3 sherlock.py username

# Online tools
https://namecheckup.com/
https://namechk.com/
https://knowem.com/
```

### Platform-Specific

**Twitter/X:**

```bash
# Advanced search
from:username since:2020-01-01 until:2023-12-31
from:username filter:images
to:username

# Timeline analysis
https://socialbearing.com/
```

**LinkedIn:**

```bash
# Find employees
site:linkedin.com "Company Name" "Security Engineer"

# Google cache for profiles
cache:linkedin.com/in/username
```

**Facebook:**

```bash
# Facebook Graph Search (limited now)
# Use Graph API
# Check tagged photos
# Review comments on public pages
```

**Instagram:**

```bash
# Location tags
# Hashtag research
# Story highlights
# Check tagged photos
```

**GitHub:**

```bash
# Search code
filename:wp-config.php password
filename:.env DB_PASSWORD
extension:pem private

# User activity
https://github.com/username?tab=repositories
https://github.com/username?tab=stars

# Commit history (for leaked secrets)
# Tool: truffleHog
trufflehog git https://github.com/user/repo
```

## Domain & IP Intelligence

### WHOIS Lookup

```bash
# Command line
whois example.com
whois 8.8.8.8

# Online tools
https://who.is/
https://whois.domaintools.com/
```

### DNS Enumeration

```bash
# DNS records
dig example.com ANY
dig example.com MX
dig example.com TXT
nslookup example.com

# Subdomain enumeration
# See reconnaissance section in main guide

# Historical DNS
https://securitytrails.com/
https://viewdns.info/
```

### IP Intelligence

```bash
# IP geolocation
curl ipinfo.io/8.8.8.8
geoiplookup 8.8.8.8

# Online tools
https://ipinfo.io/
https://www.maxmind.com/

# Reverse IP lookup (find domains on IP)
https://viewdns.info/reverseip/

# ASN lookup
whois -h whois.radb.net AS15169
```

### Certificate Transparency

```bash
# Find subdomains via certificates
https://crt.sh/?q=example.com
https://crt.sh/?q=%.example.com

# Command line
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u
```

## Image Intelligence

### Reverse Image Search

```bash
# Google Images
https://images.google.com/
# Upload or paste URL

# TinEye
https://tineye.com/

# Yandex (often better for faces)
https://yandex.com/images/

# Bing Visual Search
https://www.bing.com/visualsearch
```

### Metadata Extraction

```bash
# EXIF data
exiftool image.jpg

# Look for:
# - GPS coordinates
# - Camera model
# - Software used
# - Date/time
# - Author/Copyright

# Remove metadata
exiftool -all= image.jpg

# Online tools
http://exif.regex.info/exif.cgi
https://www.metadata2go.com/
```

### Geolocation from Images

```bash
# If GPS coordinates in EXIF
exiftool image.jpg | grep GPS

# Convert coordinates
# Decimal: 40.748817, -73.985428
# To Google Maps: https://www.google.com/maps?q=40.748817,-73.985428

# Visual landmarks
# - Street signs
# - Store names
# - Architectural features
# - Language on signs
# - License plates
# - Vegetation
```

### Tools

```bash
# GeoSocial Footprint
http://geosocialfootprint.com/

# GeoCreepy (archived but useful)
# Analyzes social media for location

# Google Earth
# For visual matching

# Overpass Turbo (OpenStreetMap)
https://overpass-turbo.eu/
```

## People Search

### Email Investigation

```bash
# Email validation
https://hunter.io/email-verifier
https://tools.emailhippo.com/

# Find emails
https://hunter.io/
https://phonebook.cz/

# Email breach check
https://haveibeenpwned.com/
https://dehashed.com/

# Email header analysis
https://mxtoolbox.com/EmailHeaders.aspx
```

### Phone Numbers

```bash
# Lookup
https://www.truecaller.com/
https://www.whitepages.com/

# Format identification
# Country code analysis

# Reverse lookup
# Can reveal carrier, location
```

### Username Investigation

```bash
# Cross-platform search
sherlock username

# GitHub
https://github.com/username

# Reddit
https://redditmetis.com/user/username

# Archive search
https://archive.org/
```

## Tools

### Essential OSINT Tools

```bash
# Maltego
# - Graphical link analysis
# - Transform data relationships
# Download: https://www.maltego.com/

# theHarvester
# - Email, subdomain enumeration
theHarvester -d example.com -b google,bing,linkedin

# Recon-ng
# - OSINT framework
# - Modular approach
recon-ng
marketplace install all
modules load recon/domains-hosts/bing_domain_web

# SpiderFoot
# - Automated OSINT
# - Web interface
spiderfoot -s example.com

# Sherlock
# - Username search across platforms
python3 sherlock.py username

# Social Analyzer
# - Profile finder
python3 social-analyzer.py --username target

# Amass
# - DNS enumeration
amass enum -d example.com
```

### Online Tools

**All-in-One:**

- https://osintframework.com/ - Directory of tools
- https://start.me/p/DPYPMz/the-ultimate-osint-collection

**Domain/IP:**

- https://viewdns.info/
- https://securitytrails.com/
- https://crt.sh/
- https://shodan.io/

**Social Media:**

- https://socialbearing.com/ (Twitter)
- https://www.social-searcher.com/
- https://twdown.net/ (Twitter media download)

**Images:**

- https://images.google.com/
- https://tineye.com/
- https://yandex.com/images/

**Archives:**

- https://archive.org/
- https://archive.is/
- https://cachedview.com/

## CTF-Specific Techniques

### 1. Image Analysis

```bash
# Extract EXIF
exiftool image.jpg

# Find GPS coordinates
exiftool image.jpg | grep GPS

# Look for hidden data
strings image.jpg
binwalk image.jpg

# Reverse image search
# Upload to Google Images
```

### 2. Username Tracking

```bash
# Check all platforms
sherlock username

# Look for:
# - Common passwords in breaches
# - Public repositories
# - Social media posts
# - Old forum posts
```

### 3. Website Investigation

```bash
# Historical versions
https://archive.org/web/

# Hidden pages
robots.txt
sitemap.xml

# Subdomains
crt.sh
subfinder
```

### 4. Document Analysis

```bash
# Extract metadata
exiftool document.pdf
strings document.pdf

# Check for:
# - Author name
# - Creation date
# - Editing software
# - Hidden text
# - Comments
```

### 5. Email Investigation

```bash
# Check breaches
https://haveibeenpwned.com/

# Find related emails
hunter.io

# Analyze headers
# Look for:
# - Sending IP
# - Mail server
# - Routing path
```

## Common CTF Patterns

### 1. GPS Coordinates

```python
# Often in EXIF data
exiftool image.jpg | grep GPS

# Convert formats
# DMS → Decimal
# Degrees Minutes Seconds → DD

# Example:
# 40° 44' 54.9" N, 73° 59' 8.3" W
# → 40.748583, -73.985639
```

### 2. Social Media Profiles

```bash
# Look for:
# - Patterns in posts
# - Check-ins (location)
# - Photos (EXIF data)
# - Connections
# - Likes/interests
```

### 3. Company/Organization Info

```bash
# Find employees
site:linkedin.com "Company Name"

# Find documents
site:company.com filetype:pdf
site:company.com filetype:docx

# Historical data
https://archive.org/
```

### 4. Timestamp Analysis

```bash
# EXIF timestamps
# Social media post times
# Domain registration dates
# SSL certificate dates

# Correlate times across sources
```

## Practice Resources

- **GeoGuessr** - https://www.geoguessr.com/ (Location identification)
- **Tracelabs** - https://www.tracelabs.org/ (OSINT CTF)
- **OSINT Exercise** - https://gralhix.com/list-of-osint-exercises/
- **Aware Online** - https://www.aware-online.com/osint-challenges/

## Quick Reference

```bash
# Google Dorks
site: filetype: inurl: intitle: intext:

# Tools
theHarvester, sherlock, maltego, recon-ng

# Image Analysis
exiftool, reverse image search, geolocate

# Domain/IP
whois, dig, nslookup, crt.sh, shodan

# Social Media
sherlock, socialbearing, hunter.io

# Archives
archive.org, archive.is, cachedview
```

## Tips

1. **Think Like the Target** - What would they post? Where?
2. **Correlate Information** - Piece together small clues
3. **Use Multiple Sources** - Cross-reference findings
4. **Check Archives** - Information might be deleted
5. **Be Thorough** - Small details matter
6. **Document Everything** - Keep track of findings
7. **Respect Privacy** - In real-world, follow ethical guidelines

Remember: OSINT is about connecting the dots from publicly available information!
