local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Second enhancement of http-security-headers, built on
http-security-headers-plus. It keeps the present / missing / deprecated header
report and adds a configuration audit that judges the header VALUES, not just
their presence:

* Strict-Transport-Security: max-age=0, max-age under one year, missing
  includeSubDomains, HSTS sent over plain HTTP
* Content-Security-Policy: 'unsafe-inline', 'unsafe-eval', wildcard sources,
  missing default-src, missing object-src
* Clickjacking: neither X-Frame-Options nor CSP frame-ancestors
* X-Content-Type-Options not set to nosniff
* X-XSS-Protection enabled (deprecated, should be 0 or absent)
* Referrer-Policy missing or set to unsafe-url
* X-Permitted-Cross-Domain-Policies: all
* Every cookie checked separately for Secure, HttpOnly and SameSite

Each finding gets a severity (HIGH, MEDIUM, LOW) and the script reports an
overall risk equal to the highest severity found.
]]

---
-- @usage
-- nmap -p 80,443 --script http-security-headers-audit <target>
--
-- @args http-security-headers-audit.path The URL path to request. Default: /
--
-- @output
-- 80/tcp open  http
-- | http-security-headers-audit:
-- |   summary: 2/9 recommended headers present
-- |   missing:
-- |     X-Frame-Options
-- |   findings:
-- |     HIGH: CSP allows 'unsafe-inline' scripts, which defeats XSS protection
-- |     MEDIUM: Cookie 'sessionid' is missing HttpOnly
-- |     LOW: Referrer-Policy is missing
-- |   counts: HIGH=1 MEDIUM=1 LOW=1
-- |_  overall_risk: HIGH

author = "Rishabh Sinha"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local ONE_YEAR = 31536000

local RECOMMENDED = {
  "Strict-Transport-Security",
  "Content-Security-Policy",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Cross-Origin-Embedder-Policy",
  "X-Permitted-Cross-Domain-Policies",
}

local DEPRECATED = {
  "X-XSS-Protection",
  "Expect-CT",
  "Public-Key-Pins",
  "Public-Key-Pins-Report-Only",
}

local SEVERITY_ORDER = {"HIGH", "MEDIUM", "LOW"}

local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function parse_csp(csp)
  local directives = {}
  for _, part in ipairs(stringaux.strsplit(";", csp)) do
    local name, sources = trim(part):match("^([%w%-]+)%s*(.*)$")
    if name then
      directives[name:lower()] = " " .. sources:lower() .. " "
    end
  end
  return directives
end

local function has_source(sources, token)
  return sources and sources:find(" " .. token .. " ", 1, true) ~= nil
end

local function check_hsts(value, is_https, add)
  if not value then
    if is_https then
      add("HIGH", "Strict-Transport-Security is missing on an HTTPS service")
    end
    return
  end
  if not is_https then
    add("LOW", "Strict-Transport-Security is sent over plain HTTP, where browsers ignore it")
    return
  end
  local max_age = tonumber(value:lower():match("max%-age%s*=%s*\"?(%d+)"))
  if not max_age then
    add("MEDIUM", "Strict-Transport-Security has no valid max-age")
  elseif max_age == 0 then
    add("HIGH", "Strict-Transport-Security max-age=0 switches HSTS off")
  elseif max_age < ONE_YEAR then
    add("MEDIUM", string.format("Strict-Transport-Security max-age is %d seconds (less than one year)", max_age))
  end
  if not value:lower():find("includesubdomains", 1, true) then
    add("LOW", "Strict-Transport-Security does not include includeSubDomains")
  end
end

local function check_csp(value, add)
  if not value then
    add("MEDIUM", "Content-Security-Policy is missing (no browser-side XSS mitigation)")
    return nil
  end
  local d = parse_csp(value)
  local script_sources = d["script-src"] or d["default-src"]
  if has_source(script_sources, "'unsafe-inline'") then
    add("HIGH", "CSP allows 'unsafe-inline' scripts, which defeats XSS protection")
  end
  if has_source(script_sources, "'unsafe-eval'") then
    add("MEDIUM", "CSP allows 'unsafe-eval' (eval() and similar are permitted)")
  end
  if has_source(script_sources, "*") or has_source(script_sources, "http:") or has_source(script_sources, "https:") then
    add("HIGH", "CSP lets scripts load from any host (wildcard or bare scheme source)")
  end
  if not d["default-src"] then
    add("LOW", "CSP has no default-src fallback directive")
  end
  if not d["object-src"] and not has_source(d["default-src"], "'none'") then
    add("LOW", "CSP does not restrict plugins (no object-src 'none')")
  end
  return d
end

local function check_cookies(cookies, is_https, add)
  for _, c in ipairs(cookies or {}) do
    local label = "Cookie '" .. c.name .. "'"
    if c.secure == nil then
      if is_https then
        add("HIGH", label .. " is missing the Secure flag on HTTPS")
      else
        add("MEDIUM", label .. " is set over plain HTTP without the Secure flag")
      end
    end
    if c.httponly == nil then
      add("MEDIUM", label .. " is missing HttpOnly (readable by JavaScript)")
    end
    if c.samesite == nil then
      add("LOW", label .. " has no SameSite attribute (CSRF protection)")
    elseif c.samesite:lower() == "none" and c.secure == nil then
      add("MEDIUM", label .. " uses SameSite=None without Secure, which browsers reject")
    end
  end
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local response = http.get(host, port, path)

  if not response or not response.status or not response.header then
    return stdnse.format_output(false, "No valid HTTP response")
  end

  local h = response.header
  local is_https = shortport.ssl(host, port)

  local present, missing, deprecated = {}, {}, {}
  local applicable, counted = 0, 0
  for _, name in ipairs(RECOMMENDED) do
    local value = h[name:lower()]
    local applies = name ~= "Strict-Transport-Security" or is_https
    if value then
      present[#present + 1] = name .. ": " .. value
    end
    if applies then
      applicable = applicable + 1
      if value then
        counted = counted + 1
      else
        missing[#missing + 1] = name
      end
    end
  end
  for _, name in ipairs(DEPRECATED) do
    if h[name:lower()] then
      deprecated[#deprecated + 1] = name .. ": " .. h[name:lower()]
    end
  end

  local findings = {HIGH = {}, MEDIUM = {}, LOW = {}}
  local function add(severity, text)
    table.insert(findings[severity], text)
  end

  check_hsts(h["strict-transport-security"], is_https, add)
  local csp = check_csp(h["content-security-policy"], add)

  if not h["x-frame-options"] and not (csp and csp["frame-ancestors"]) then
    add("MEDIUM", "No X-Frame-Options or CSP frame-ancestors (clickjacking possible)")
  end

  local xcto = h["x-content-type-options"]
  if not xcto then
    add("LOW", "X-Content-Type-Options is missing (MIME sniffing allowed)")
  elseif trim(xcto):lower() ~= "nosniff" then
    add("LOW", "X-Content-Type-Options is not set to nosniff")
  end

  local xxss = h["x-xss-protection"]
  if xxss and trim(xxss):sub(1, 1) ~= "0" then
    add("LOW", "X-XSS-Protection is enabled; this filter is deprecated and should be 0 or removed")
  end

  local referrer = h["referrer-policy"]
  if not referrer then
    add("LOW", "Referrer-Policy is missing (full URLs may leak to other sites)")
  elseif referrer:lower():find("unsafe-url", 1, true) then
    add("MEDIUM", "Referrer-Policy is unsafe-url (full URLs always leak)")
  end

  local xpcdp = h["x-permitted-cross-domain-policies"]
  if xpcdp and trim(xpcdp):lower() == "all" then
    add("MEDIUM", "X-Permitted-Cross-Domain-Policies is 'all' (any policy file accepted)")
  end

  check_cookies(response.cookies, is_https, add)

  local out = stdnse.output_table()
  out.summary = string.format("%d/%d recommended headers present", counted, applicable)
  out.present = present
  out.missing = missing
  if #deprecated > 0 then
    out.deprecated = deprecated
  end

  local listed, counts, overall = {}, {}, "NONE"
  for _, severity in ipairs(SEVERITY_ORDER) do
    for _, text in ipairs(findings[severity]) do
      listed[#listed + 1] = severity .. ": " .. text
    end
    counts[#counts + 1] = severity .. "=" .. #findings[severity]
    if overall == "NONE" and #findings[severity] > 0 then
      overall = severity
    end
  end

  out.findings = listed
  out.counts = table.concat(counts, " ")
  out.overall_risk = overall
  return out
end
