# http-recon-misconfig.nse

A smart, production-ready Nmap NSE script for HTTP/HTTPS recon and basic misconfiguration detection.

> **Category:** Recon & Basic Misconfiguration  
> **Author:** 7nhn  
> **License:** Same as Nmap

<p align="right">
  <a href="./README.tr.md">🇹🇷 Türkçe README için tıklayın</a>
</p>

---

## What It Does

Performs passive, non-intrusive reconnaissance against HTTP/HTTPS services. No brute-force, no injection — just smart header and response analysis.

| # | Check | Description |
|---|-------|-------------|
| 1 | **Tech Fingerprinting** | Detects server, framework, and CMS from `Server`, `X-Powered-By`, `Set-Cookie`, `Via`, and HTML body |
| 2 | **Security Headers** | Flags missing `X-Frame-Options`, `X-Content-Type-Options`, `CSP`, `HSTS` |
| 3 | **HTTP Methods** | Sends `OPTIONS`, warns on `PUT`, `DELETE`, `TRACE` |
| 4 | **Sensitive Files** | Checks 20 paths like `/.env`, `/.git/`, `/backup.zip`, `/id_rsa` |
| 5 | **Interesting Paths** | Probes 24 paths like `/admin`, `/graphql`, `/actuator` (200 or 403) |
| 6 | **robots.txt** | Parses and reports all `Disallow` entries |
| 7 | **Directory Listing** | Detects `Index of /` and `Parent Directory` in response body |
| 8 | **Login Page Detection** | Identifies login forms via HTML patterns |
| 9 | **Favicon Hash** | Computes FNV-1a hash of `/favicon.ico` for passive fingerprinting |
| 10 | **HTTPS Redirect** | Checks if HTTP redirects to HTTPS |
| 11 | **CORS Policy** | Warns on `Access-Control-Allow-Origin: *` |

---

## Installation

```bash
cp http-recon-misconfig.nse /usr/share/nmap/scripts/
nmap --script-updatedb
```

---

## Usage

```bash
# Single target
nmap -p 80,443 --script http-recon-misconfig.nse <target>

# With service detection
nmap -sV -p 80,443 --script http-recon-misconfig.nse <target>

# Custom user-agent
nmap -p 80 --script http-recon-misconfig.nse \
  --script-args http.useragent="Mozilla/5.0" <target>
```

---

## Sample Output

```
PORT   STATE SERVICE
80/tcp open  http
| http-recon-misconfig:
|   [+] Server: nginx/1.18.0
|   [+] X-Powered-By: PHP/8.1.2
|   [INFO] Detected Tech: nginx + PHP + WordPress
|   [+] Version: 1.18.0
|   [!] Missing X-Frame-Options
|   [!] Missing Content-Security-Policy
|   [!] Missing Strict-Transport-Security
|   [MEDIUM] Permissive CORS policy detected (Access-Control-Allow-Origin: *)
|   [HIGH] Directory listing enabled on /
|   [+] Allowed Methods: GET, POST, PUT, DELETE
|   [!] Dangerous method allowed: PUT
|   [!] Dangerous method allowed: DELETE
|   [INFO] Redirects to HTTPS: https://example.com/
|   [!] Sensitive file exposed: /.env
|   [!] Sensitive file exposed: /backup.zip
|   [INFO] Login page detected: /login
|   [+] Interesting path found: /login (HTTP 200)
|   [+] Interesting path found: /admin (HTTP 403)
|   [+] robots.txt Disallow entries: /admin, /private, /backup
|_  [INFO] Favicon hash (FNV-1a): 3d2a1f8e
```

---

## Output Prefixes

| Prefix | Meaning |
|--------|---------|
| `[+]` | Informational finding |
| `[INFO]` | Passive observation |
| `[!]` | Misconfiguration / missing control |
| `[MEDIUM]` | Medium severity issue |
| `[HIGH]` | High severity issue |

---

## Detected Technologies

The fingerprinting engine covers 30+ patterns across 5 sources:

- **Web servers:** nginx, Apache, IIS, LiteSpeed, Caddy, Jetty, Tomcat, OpenResty
- **Languages:** PHP, ASP.NET, Java, Node.js / Express, Next.js
- **Frameworks:** Laravel, Django, WordPress, Drupal, Joomla
- **Frontend:** React, Vue.js, Angular
- **Proxies:** Varnish, Squid

---

## Constraints

This script intentionally does **not** perform:

- Brute-force attacks
- SQL injection or XSS attempts
- Rate limit testing
- Heavy wordlist scanning

---

## Requirements

- Nmap 7.x+
- NSE modules: `shortport`, `http`, `stdnse`
