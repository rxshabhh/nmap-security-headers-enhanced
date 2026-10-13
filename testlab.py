import os
import ssl
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Local test lab for the DA3 Nmap scripts. Runs only on 127.0.0.1.
# Usage:  python testlab.py weak     (misconfigured server)
#         python testlab.py strong   (well configured server)
# HTTP on port 8008, HTTPS on port 8443 (self-signed test certificate).

PROFILES = {
    "weak": [
        ("Server", "Apache/2.4.7 (Ubuntu)"),
        ("Strict-Transport-Security", "max-age=60"),
        ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; manifest-src 'self'"),
        ("X-XSS-Protection", "1; mode=block"),
        ("X-Permitted-Cross-Domain-Policies", "by-content-type"),
        ("Referrer-Policy", "unsafe-url"),
        ("Set-Cookie", "sessionid=abc123; Path=/"),
        ("Set-Cookie", "theme=dark; Path=/; HttpOnly"),
    ],
    "strong": [
        ("Server", "Apache"),
        ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; manifest-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("X-Permitted-Cross-Domain-Policies", "none"),
        ("Set-Cookie", "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"),
    ],
}

CERT = """-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUeQklnxwMC1OQ13ERNEVSkqFlbpswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxMzE4MTQwN1oXDTM2MTAx
MDE4MTQwN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAxoTv8R8eVNl4FzezpZnqhS9NMMat6RcKRiUtotbH6UfZ
9/ljQD6yBKZS/SLq/kTh107ti3BhOAHPHSfD6vktODlAKadeR3w/I80EWX7ScQFp
aIpz+FuopRssKmTj0tagFMpe7sH+IVZIDSlKKLmlLVqdLlMmMj305EjNIT5j4g/8
jLNciUQ4Jf6qfHA6U7KsPyT9e1w7HOAOZ6XgVkonMfP1VKvU9RM4s9IxSxTcOem7
36o7n+LgFB6tnP+noOGva+dLnmvX2nE0V4ONEiNbLegOZdo+1P1hkjIuzsBnWXDC
3dvd6BOV6SgmlRTRmPXn4A2QituDYMD08OyE2Ca4kwIDAQABo1MwUTAdBgNVHQ4E
FgQULd4OVg+pN2pv3D+d0xpHEX4mqiQwHwYDVR0jBBgwFoAULd4OVg+pN2pv3D+d
0xpHEX4mqiQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAo77I
V4HHsZyr6wfWY8SlX6szM0I4PGIYi6ph1ZqRUfN3dTfYR7eTbU1Ai4WRxx5H4aXp
uvvSRQkqkcBCjW5t72xBU7O/14gOxsSWY+FdoJf0a13MJfm2ou0D59xRr7UIWJPV
v1ONsiosdt0tC7ciQwT0X8we2BCZv9b91HFAvHjSYtciG5XkxngvhosdWWYdMC09
lY/i3EAhebm8VoXniLw1j84GCvLijZvmB4cultvRwPHAZdlMYpNxifiCgL7uP/qo
e9YcRWHmOIoBTlt5Kz/qSvbLoO/mwG5Yt1VjNPrmmTTKuMy8kc6m+6lECRMhQytx
6GdwGpzRfAx/kkvShw==
-----END CERTIFICATE-----"""

KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGhO/xHx5U2XgX
N7OlmeqFL00wxq3pFwpGJS2i1sfpR9n3+WNAPrIEplL9Iur+ROHXTu2LcGE4Ac8d
J8Pq+S04OUApp15HfD8jzQRZftJxAWloinP4W6ilGywqZOPS1qAUyl7uwf4hVkgN
KUoouaUtWp0uUyYyPfTkSM0hPmPiD/yMs1yJRDgl/qp8cDpTsqw/JP17XDsc4A5n
peBWSicx8/VUq9T1Eziz0jFLFNw56bvfqjuf4uAUHq2c/6eg4a9r50uea9facTRX
g40SI1st6A5l2j7U/WGSMi7OwGdZcMLd293oE5XpKCaVFNGY9efgDZCK24NgwPTw
7ITYJriTAgMBAAECggEAGrYVcPIOdeftsYtkUo0jZ03w4CDDksBFDiDU2KXMsAC5
J+q4UOh+sdh4BH6CdGRr/OQDsMZAwTVLxcZYJWbnZOVzKDJQdw7qkf8f2DOTzkfH
Lp1T3bWQ5hJXaXw6GWBD7uLh+NSab1LkOVJ2cNoLNc83pLLkdKXYgdpNMO1rqXrf
GPcd+iWa2L/60DZTS4cAdbIAELue5upO756UZo9IpdMg1STHX2ok/cqWfhpZPZGw
pF2Ht5DV73tUxY2Fsh8jH2wtVsWVjfLXT3n/ePQAhMEdOpRhRb4Y1OWqALlbeCve
JBR7V2YGO5KeSick/d4AXMfYlTWsd8U4Fa62X8y7sQKBgQD90VmSvBbBrmdzAM+a
6CwScttIvYThMlp32YgOJmGUE3Bv1PvEfU47aEZvUH/BFjoB9ZaMmmnvxAIbszXw
MaXRZTNKCzoV5b4332fKi+OaFz9aN2Ag+E8btJtDOebB9I/dYtk+khhNGdSMWEe4
Z/Qwq9MQwqXEA5cRZrgRnF2FowKBgQDIOeBC7i71QmMEZvVL1GCG6tRk2eniM3OC
znaT7RkYDIQml+zl9L9SSjy7ZJf601IuqmlrYFyujuhUv5K+dytDn4mm7CIMGF3j
jmPzovYfcj43/HpJE2/dJC7t6XmGEtny7Z74lJ/pEpOJnAFdTrShuPsqzUwlBHur
IDf7B8nQUQKBgQDtr+qt2q2E2onNzGidq+X5sM1hJPkW2kyWB4O9nHusazfTwiOz
MZTdVR0AiOXaL7JKu20sZj3mZiuDPSO5twSNPrP1FuZiMy8aq39K0g1l83dESK8g
sOeEDnGHVuWdpCRFMZg3XCCdsx6z/sfLDK5EFeQlweHx2VrS1Npyw3dg+QKBgGvL
lOwTtV4/TnWpRHh9rzYTqSNemmc4kgCjTP2Y0UC8RE1Oz7CB0prn8shkgNn9+Sm8
fyLa7yrfLz+pH8TA/Z7bfk1KpY3jdHC1USRy4JTPeaXEnMVI3JmvCED3yIAhGAuM
WGC2C118rceRIL7uR5slrrs9abgoMLhRkTHp4IHxAoGBAOmF1WnNtXGK4cRQwkFB
JxKKXVyOQ7lnxIThVHyS/KL0vUtCRAb7VdH/OdOLlCdAFl1QbDtrHldgbf2LZua9
cIUwqUUXoXqeZ8j4LpXq0DqzGlNVFjbm2ih/9LaFlF4ooDwzvx7LH84N1CmpuPwS
PV4ThZj7BXcfGc3z37sXcuEc
-----END PRIVATE KEY-----"""

MODE = sys.argv[1] if len(sys.argv) > 1 else "weak"
if MODE not in PROFILES:
    sys.exit("Usage: python testlab.py weak|strong")

BODY = b"<html><head><title>DA3 Test Lab</title></head><body>Test page</body></html>"


class Handler(BaseHTTPRequestHandler):
    def _respond(self, with_body):
        self.send_response_only(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        for name, value in PROFILES[MODE]:
            self.send_header(name, value)
        self.end_headers()
        if with_body:
            self.wfile.write(BODY)

    def do_GET(self):
        self._respond(True)

    def do_HEAD(self):
        self._respond(False)

    def log_message(self, *args):
        pass


def serve_https():
    folder = tempfile.mkdtemp()
    cert_path = os.path.join(folder, "cert.pem")
    key_path = os.path.join(folder, "key.pem")
    with open(cert_path, "w") as f:
        f.write(CERT)
    with open(key_path, "w") as f:
        f.write(KEY)
    server = ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


threading.Thread(target=serve_https, daemon=True).start()
print("DA3 test lab running in '%s' mode" % MODE)
print("  HTTP : 127.0.0.1:8008")
print("  HTTPS: 127.0.0.1:8443")
print("Press Ctrl+C to stop.")
try:
    ThreadingHTTPServer(("127.0.0.1", 8008), Handler).serve_forever()
except KeyboardInterrupt:
    pass
