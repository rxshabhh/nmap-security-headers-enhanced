# nmap-security-headers-enhanced

Two enhanced versions of Nmap's `http-security-headers` NSE script, plus a local test lab.

## Why

The original `http-security-headers` script:

1. gives no output for a server that sends no security headers ("no string output")
2. ignores Referrer-Policy, Permissions-Policy and the Cross-Origin-* policies
3. prints header values without judging them (HSTS max-age=60, CSP with 'unsafe-inline')
4. describes the deprecated X-XSS-Protection header as a protection
5. never reports insecure cookies
6. has two bugs: it searches CSP for `mailfest.src` instead of `manifest-src`, and shows the wrong text for `X-Permitted-Cross-Domain-Policies: by-content-type`

## Scripts

| File | What it does |
|---|---|
| `http-security-headers-plus.nse` | Enhancement 1: reports present, missing and deprecated headers, adds modern headers, fixes both bugs |
| `http-security-headers-audit.nse` | Enhancement 2 (built on 1): audits HSTS, CSP and every cookie, and gives HIGH/MEDIUM/LOW findings with an overall risk |
| `testlab.py` | Local test server (127.0.0.1 only), `weak` or `strong` mode, HTTP 8008 and HTTPS 8443 |

## Usage

```
python testlab.py weak
nmap -Pn -p 8008 --script http-security-headers-plus.nse 127.0.0.1
nmap -Pn -p 8008,8443 --script http-security-headers-audit.nse 127.0.0.1
```

Scan only hosts you own or are allowed to test (for example scanme.nmap.org).

Author: Rishabh Sinha
