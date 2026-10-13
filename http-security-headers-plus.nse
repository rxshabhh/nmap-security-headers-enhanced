local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Enhanced version of http-security-headers. Reports which recommended HTTP
security headers are present AND which are missing, so a server that sends no
security headers at all still produces a clear report instead of no output.

Compared to http-security-headers it also:
* checks modern headers: Referrer-Policy, Permissions-Policy,
  Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy and
  Cross-Origin-Embedder-Policy
* lists deprecated headers (X-XSS-Protection, Expect-CT, Public-Key-Pins)
  separately instead of describing them as protections
* parses every Content-Security-Policy directive, fixing the original
  "mailfest-src" typo that made manifest-src invisible
* gives the correct meaning of X-Permitted-Cross-Domain-Policies: by-content-type
* marks Strict-Transport-Security as not applicable on plain HTTP, where
  browsers ignore it
]]

---
-- @usage
-- nmap -p 80,443 --script http-security-headers-plus <target>
--
-- @args http-security-headers-plus.path The URL path to request. Default: /
--
-- @output
-- 80/tcp open  http
-- | http-security-headers-plus:
-- |   present:
-- |     Content-Security-Policy: default-src 'self'
-- |   missing:
-- |     X-Frame-Options
-- |     X-Content-Type-Options
-- |   not_applicable:
-- |     Strict-Transport-Security (only honoured over HTTPS)
-- |   csp_directives: default-src
-- |_  summary: 1/9 recommended headers present

author = "Rishabh Sinha"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

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

local CROSS_DOMAIN_MEANING = {
  ["none"] = "no cross-domain policy files are allowed",
  ["master-only"] = "only the master policy file is allowed",
  ["by-content-type"] = "only policy files served as text/x-cross-domain-policy are allowed",
  ["by-ftp-filename"] = "only policy files named crossdomain.xml are allowed (FTP)",
  ["all"] = "any policy file on the domain is allowed",
}

local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function csp_directive_names(csp)
  local names = {}
  for _, part in ipairs(stringaux.strsplit(";", csp)) do
    local name = trim(part):match("^([%w%-]+)")
    if name then
      names[#names + 1] = name:lower()
    end
  end
  return names
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local response = http.get(host, port, path)

  if not response or not response.status or not response.header then
    return stdnse.format_output(false, "No valid HTTP response")
  end

  local is_https = shortport.ssl(host, port)
  local present, missing, not_applicable, deprecated = {}, {}, {}, {}
  local applicable_total = 0

  for _, name in ipairs(RECOMMENDED) do
    local value = response.header[name:lower()]
    if name == "Strict-Transport-Security" and not is_https then
      not_applicable[#not_applicable + 1] = name .. " (only honoured over HTTPS)"
      if value then
        present[#present + 1] = name .. ": " .. value
      end
    else
      applicable_total = applicable_total + 1
      if value then
        present[#present + 1] = name .. ": " .. value
      else
        missing[#missing + 1] = name
      end
    end
  end

  for _, name in ipairs(DEPRECATED) do
    local value = response.header[name:lower()]
    if value then
      deprecated[#deprecated + 1] = name .. ": " .. value
    end
  end

  local out = stdnse.output_table()
  out.present = present
  out.missing = missing
  if #not_applicable > 0 then
    out.not_applicable = not_applicable
  end
  if #deprecated > 0 then
    out.deprecated = deprecated
  end

  local csp = response.header["content-security-policy"]
  if csp then
    out.csp_directives = table.concat(csp_directive_names(csp), ", ")
  end

  local xpcdp = response.header["x-permitted-cross-domain-policies"]
  if xpcdp then
    out.cross_domain_policy = CROSS_DOMAIN_MEANING[trim(xpcdp):lower()] or "unrecognised value"
  end

  local counted = 0
  for _, name in ipairs(RECOMMENDED) do
    if response.header[name:lower()] and (name ~= "Strict-Transport-Security" or is_https) then
      counted = counted + 1
    end
  end
  out.summary = string.format("%d/%d recommended headers present", counted, applicable_total)

  return out
end
