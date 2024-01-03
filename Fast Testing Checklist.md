# Fast Testing Checklist

A combination of my own methodology and the Web Application Hacker's Handbook Task checklist, as a Github-Flavored Markdown file

# Contents

- [Fast Testing Checklist](#fast-testing-checklist)
- [Contents](#contents)
- [Task Checklist](#task-checklist)
  - [App Recon and analysis](#app-recon-and-analysis)
  - [Test handling of access](#test-handling-of-access)
    - [- \[ \] Authentication](#----authentication)
    - [- \[ \] Session handling](#----session-handling)
    - [- \[ \] Access controls](#----access-controls)
  - [Test handling of input](#test-handling-of-input)
  - [Test application logic](#test-application-logic)
  - [Assess application hosting](#assess-application-hosting)
  - [Miscellaneous tests](#miscellaneous-tests)

# Task Checklist

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

### - [ ] Authentication

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

### - [ ] Session Handling

- [ ] Test tokens for meaning
- [ ] Test tokens for predictability
- [ ] Check for insecure transmission of tokens
- [ ] Check for disclosure of tokens in logs
- [ ] Check mapping of tokens to sessions
- [ ] Check session termination
- [ ] Check for session fixation
- [ ] Check for cross-site request forgery
- [ ] Check cookie scope

### - [ ] Access Controls

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
