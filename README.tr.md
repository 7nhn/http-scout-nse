# http-recon-misconfig.nse

HTTP/HTTPS servisleri için akıllı bir Nmap NSE recon ve yanlış yapılandırma tespit scripti.

> **Kategori:** Recon & Temel Yanlış Yapılandırma  
> **Geliştirici:** 7nhn 

---

## Ne Yapar?

HTTP/HTTPS servislerine karşı pasif, müdahalesiz keşif gerçekleştirir. Brute-force yok, injection yok — sadece akıllı header ve response analizi.

| # | Kontrol | Açıklama |
|---|---------|----------|
| 1 | **Teknoloji Tespiti** | `Server`, `X-Powered-By`, `Set-Cookie`, `Via` ve HTML body üzerinden sunucu, framework ve CMS tespiti |
| 2 | **Güvenlik Header'ları** | Eksik `X-Frame-Options`, `X-Content-Type-Options`, `CSP`, `HSTS` uyarısı |
| 3 | **HTTP Metodları** | `OPTIONS` isteği atar, `PUT`, `DELETE`, `TRACE` varsa uyarır |
| 4 | **Hassas Dosyalar** | `/.env`, `/.git/`, `/backup.zip`, `/id_rsa` dahil 20 path kontrolü |
| 5 | **İlginç Path'ler** | `/admin`, `/graphql`, `/actuator` dahil 24 path taraması (200 veya 403) |
| 6 | **robots.txt** | Tüm `Disallow` satırlarını parse edip raporlar |
| 7 | **Dizin Listeleme** | Response body'de `Index of /` ve `Parent Directory` tespiti |
| 8 | **Login Sayfası Tespiti** | HTML pattern analizi ile login form tespiti |
| 9 | **Favicon Hash** | `/favicon.ico` için FNV-1a hash hesaplar (pasif fingerprinting) |
| 10 | **HTTPS Yönlendirme** | HTTP'nin HTTPS'e yönlendirip yönlendirmediğini kontrol eder |
| 11 | **CORS Politikası** | `Access-Control-Allow-Origin: *` için uyarı verir |

---

## Kurulum

```bash
cp http-recon-misconfig.nse /usr/share/nmap/scripts/
nmap --script-updatedb
```

---

## Kullanım

```bash
# Tek hedef
nmap -p 80,443 --script http-recon-misconfig.nse <hedef>

# Servis tespiti ile birlikte
nmap -sV -p 80,443 --script http-recon-misconfig.nse <hedef>

# Özel user-agent ile
nmap -p 80 --script http-recon-misconfig.nse \
  --script-args http.useragent="Mozilla/5.0" <hedef>
```

---

## Örnek Çıktı

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

## Çıktı Ön Ekleri

| Ön Ek | Anlamı |
|-------|--------|
| `[+]` | Bilgilendirici bulgu |
| `[INFO]` | Pasif gözlem |
| `[!]` | Yanlış yapılandırma / eksik kontrol |
| `[MEDIUM]` | Orta seviye güvenlik sorunu |
| `[HIGH]` | Yüksek seviye güvenlik sorunu |

---

## Tespit Edilen Teknolojiler

Fingerprinting motoru 5 farklı kaynaktan 30+ pattern tarar:

- **Web sunucuları:** nginx, Apache, IIS, LiteSpeed, Caddy, Jetty, Tomcat, OpenResty
- **Diller:** PHP, ASP.NET, Java, Node.js / Express, Next.js
- **Framework'ler:** Laravel, Django, WordPress, Drupal, Joomla
- **Frontend:** React, Vue.js, Angular
- **Proxy'ler:** Varnish, Squid

---

## Kısıtlamalar

Bu script kasıtlı olarak şunları **yapmaz**:

- Brute-force saldırısı
- SQL injection veya XSS denemesi
- Rate limit testi
- Ağır wordlist taraması

---

## Gereksinimler

- Nmap 7.x+
- NSE modülleri: `shortport`, `http`, `stdnse`
