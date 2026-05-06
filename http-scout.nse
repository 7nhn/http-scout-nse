-- http-scout.nse
-- Author: 7nhn
--
-- Smart HTTP/HTTPS recon & basic misconfiguration detection script.
-- Checks: server fingerprinting (multi-source), security headers,
-- dangerous HTTP methods, sensitive file exposure, interesting paths,
-- robots.txt, directory listing, login page detection, favicon hash,
-- HTTP→HTTPS redirect, and CORS policy.

local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local string    = require "string"
local table     = require "table"

description = [[
Smart recon and basic misconfiguration checks for HTTP/HTTPS services.
Performs multi-source technology fingerprinting (Server, X-Powered-By,
Set-Cookie, Via, HTML body), security header analysis, dangerous method
detection, sensitive file/path discovery, directory listing detection,
login page detection, favicon hash, HTTP→HTTPS redirect check, and
permissive CORS detection.

Safe, non-intrusive. No brute-force or injection attempts.
]]

author     = "7nhn"
categories = { "discovery" }

portrule = shortport.http

-- ─── Constants ───────────────────────────────────────────────────────────────

local SECURITY_HEADERS = {
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Content-Security-Policy",
  "Strict-Transport-Security",
}

local SENSITIVE_PATHS = {
  "/.git/", "/.env", "/.svn/", "/config.php",
  "/.env.backup", "/.env.old", "/.env.local",
  "/backup.zip", "/backup.tar.gz", "/db.sql",
  "/dump.sql", "/.htaccess", "/web.config",
  "/id_rsa", "/.DS_Store", "/composer.json",
  "/package.json", "/.gitignore", "/Dockerfile",
  "/docker-compose.yml", "/phpinfo.php",
}

local INTERESTING_PATHS = {
  "/admin", "/panel", "/login", "/dashboard",
  "/cpanel", "/manager", "/backend",
  "/api", "/v1", "/graphql",
  "/.well-known", "/server-status",
  "/phpinfo.php", "/wp-admin", "/wp-login.php",
  "/administrator", "/user", "/account",
  "/console", "/actuator", "/health",
  "/metrics", "/debug", "/test",
}

-- ─── Tech fingerprint patterns ───────────────────────────────────────────────
-- Each entry: { source, pattern, label }
-- source: "server" | "powered" | "cookie" | "via" | "body"

local TECH_PATTERNS = {
  -- Web servers (Server header)
  { "server", "nginx",           "nginx"      },
  { "server", "Apache",          "Apache"     },
  { "server", "Microsoft%-IIS",  "IIS"        },
  { "server", "LiteSpeed",       "LiteSpeed"  },
  { "server", "Caddy",           "Caddy"      },
  { "server", "Jetty",           "Jetty"      },
  { "server", "Tomcat",          "Tomcat"     },
  { "server", "openresty",       "OpenResty"  },
  -- Languages / frameworks (X-Powered-By)
  { "powered", "PHP",            "PHP"        },
  { "powered", "ASP%.NET",       "ASP.NET"    },
  { "powered", "Express",        "Express"    },
  { "powered", "Next%.js",       "Next.js"    },
  { "powered", "Servlet",        "Java"       },
  -- Session cookies
  { "cookie", "PHPSESSID",       "PHP"        },
  { "cookie", "JSESSIONID",      "Java"       },
  { "cookie", "ASP%.NET_Session","ASP.NET"    },
  { "cookie", "laravel_session", "Laravel"    },
  { "cookie", "django",          "Django"     },
  -- Via header
  { "via",    "nginx",           "nginx"      },
  { "via",    "Varnish",         "Varnish"    },
  { "via",    "Squid",           "Squid"      },
  -- HTML body
  { "body",   "wp%-content",     "WordPress"  },
  { "body",   "wp%-json",        "WordPress"  },
  { "body",   "Drupal",          "Drupal"     },
  { "body",   "Joomla",          "Joomla"     },
  { "body",   "laravel",         "Laravel"    },
  { "body",   "django",          "Django"     },
  { "body",   "React",           "React"      },
  { "body",   "Vue%.js",         "Vue.js"     },
  { "body",   "Angular",         "Angular"    },
  { "body",   "generator.*WordPress", "WordPress" },
}

local DANGEROUS_METHODS = { PUT = true, DELETE = true, TRACE = true }

-- ─── Helpers ─────────────────────────────────────────────────────────────────

local function get_header(response, name)
  if not (response and response.header) then return nil end
  return response.header[name:lower()]
end

local function safe_get(host, port, path)
  local ok, res = pcall(http.get, host, port, path, { timeout = 5000 })
  if ok and res and res.status then return res end
  return nil
end

-- Simple non-cryptographic hash for favicon (FNV-1a 32-bit)
local function fnv1a(data)
  local hash = 2166136261
  for i = 1, #data do
    hash = ((hash ~ data:byte(i)) * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

-- ─── 1. Multi-source Technology Fingerprinting ───────────────────────────────

local function fingerprint_tech(response, output)
  local server  = get_header(response, "Server") or ""
  local powered = get_header(response, "X-Powered-By") or ""
  local cookie  = get_header(response, "Set-Cookie") or ""
  local via     = get_header(response, "Via") or ""
  local body    = (response.body or ""):sub(1, 8192) -- scan first 8KB only

  local sources = {
    server  = server,
    powered = powered,
    cookie  = cookie,
    via     = via,
    body    = body,
  }

  -- Report raw headers
  if server  ~= "" then table.insert(output, "[+] Server: " .. server) end
  if powered ~= "" then table.insert(output, "[+] X-Powered-By: " .. powered) end

  -- Collect unique detected technologies
  local seen = {}
  local detected = {}
  for _, pat in ipairs(TECH_PATTERNS) do
    local src, pattern, label = pat[1], pat[2], pat[3]
    if not seen[label] and sources[src] and sources[src]:find(pattern) then
      seen[label] = true
      table.insert(detected, label)
    end
  end

  if #detected > 0 then
    table.insert(output, "[INFO] Detected Tech: " .. table.concat(detected, " + "))
  end

  -- Version from Server header
  local version = server:match("/([%d][%d%.]+)")
  if version then
    table.insert(output, "[+] Version: " .. version)
  end
end

-- ─── 2. Security Headers ─────────────────────────────────────────────────────

local function check_security_headers(response, output)
  for _, hdr in ipairs(SECURITY_HEADERS) do
    if not get_header(response, hdr) then
      table.insert(output, "[!] Missing " .. hdr)
    end
  end
end

-- ─── 3. HTTP Methods ─────────────────────────────────────────────────────────

local function check_methods(host, port, output)
  local ok, res = pcall(http.generic_request, host, port, "OPTIONS", "/", { timeout = 5000 })
  if not (ok and res and res.status) then return end

  local allow = get_header(res, "Allow")
  if not allow then return end

  table.insert(output, "[+] Allowed Methods: " .. allow)
  for method in allow:gmatch("[A-Z]+") do
    if DANGEROUS_METHODS[method] then
      table.insert(output, "[!] Dangerous method allowed: " .. method)
    end
  end
end

-- ─── 4. Sensitive Files ──────────────────────────────────────────────────────

local function check_sensitive_files(host, port, output)
  for _, path in ipairs(SENSITIVE_PATHS) do
    local res = safe_get(host, port, path)
    if res and res.status == 200 then
      table.insert(output, "[!] Sensitive file exposed: " .. path)
    end
  end
end

-- ─── 5. Interesting Paths ────────────────────────────────────────────────────

local function check_interesting_paths(host, port, output)
  for _, path in ipairs(INTERESTING_PATHS) do
    local res = safe_get(host, port, path)
    if res and (res.status == 200 or res.status == 403) then
      -- Login page detection on 200 responses
      if res.status == 200 and res.body then
        local b = res.body:lower()
        if b:find('type="password"') or b:find("type='password'")
          or b:find("signin") or b:find("log in") then
          table.insert(output, "[INFO] Login page detected: " .. path)
        end
      end
      table.insert(output, string.format("[+] Interesting path found: %s (HTTP %d)", path, res.status))
    end
  end
end

-- ─── 6. robots.txt ───────────────────────────────────────────────────────────

local function check_robots(host, port, output)
  local res = safe_get(host, port, "/robots.txt")
  if not (res and res.status == 200 and res.body) then return end

  local found = {}
  for line in res.body:gmatch("[^\r\n]+") do
    local path = line:match("^%s*[Dd]isallow%s*:%s*(%S+)")
    if path and path ~= "/" and path ~= "" then
      table.insert(found, path)
    end
  end

  if #found > 0 then
    table.insert(output, "[+] robots.txt Disallow entries: " .. table.concat(found, ", "))
  end
end

-- ─── 7. Directory Listing Detection ─────────────────────────────────────────

local function check_directory_listing(response, output)
  if not (response and response.body) then return end
  local b = response.body
  if b:find("Index of /", 1, true) or b:find("Parent Directory", 1, true) then
    table.insert(output, "[HIGH] Directory listing enabled on /")
  end
end

-- ─── 8. Favicon Hash ─────────────────────────────────────────────────────────

local function check_favicon(host, port, output)
  local res = safe_get(host, port, "/favicon.ico")
  if not (res and res.status == 200 and res.body and #res.body > 0) then return end
  local hash = fnv1a(res.body)
  table.insert(output, "[INFO] Favicon hash (FNV-1a): " .. hash)
end

-- ─── 9. HTTP → HTTPS Redirect ────────────────────────────────────────────────

local function check_https_redirect(host, port, output)
  -- Only relevant on plain HTTP (port 80 or non-SSL)
  if port.service == "https" or port.version and port.version.service_tunnel == "ssl" then
    return
  end
  local res = safe_get(host, port, "/")
  if not res then return end
  if (res.status == 301 or res.status == 302) then
    local loc = get_header(res, "Location") or ""
    if loc:find("^https://") then
      table.insert(output, "[INFO] Redirects to HTTPS: " .. loc)
    end
  end
end

-- ─── 10. CORS Policy ─────────────────────────────────────────────────────────

local function check_cors(response, output)
  local acao = get_header(response, "Access-Control-Allow-Origin")
  if not acao then return end
  if acao == "*" then
    table.insert(output, "[MEDIUM] Permissive CORS policy detected (Access-Control-Allow-Origin: *)")
  else
    table.insert(output, "[INFO] CORS origin: " .. acao)
  end
end

-- ─── Main Action ─────────────────────────────────────────────────────────────

action = function(host, port)
  local output = {}

  local base = safe_get(host, port, "/")
  if not base then
    return stdnse.format_output(false, "Could not connect to target")
  end

  fingerprint_tech(base, output)
  check_security_headers(base, output)
  check_cors(base, output)
  check_directory_listing(base, output)
  check_methods(host, port, output)
  check_https_redirect(host, port, output)
  check_sensitive_files(host, port, output)
  check_interesting_paths(host, port, output)
  check_robots(host, port, output)
  check_favicon(host, port, output)

  if #output == 0 then
    return stdnse.format_output(true, "No findings.")
  end

  return stdnse.format_output(true, output)
end
