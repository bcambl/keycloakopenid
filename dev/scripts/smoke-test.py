#!/usr/bin/env python3
"""Exercise the local Keycloak -> Traefik plugin -> example apps flow."""

import html
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


APP_HOSTS = {"helloworld1.localhost", "helloworld2.localhost"}

# Each client registers one fixed callback. The plugin sends this exact URI to
# Keycloak as redirect_uri and restores the original path afterwards.
CALLBACK_URLS = {
    "helloworld1.localhost": "http://helloworld1.localhost:8000/callback",
    "helloworld2.localhost": "http://helloworld2.localhost:8000/callback",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, new_url):
        return None


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs.get("action")


opener = urllib.request.build_opener(NoRedirect())
keycloak_cookies = {}


def request(url, data=None, headers=None, method=None):
    headers = dict(headers or {})
    parsed = urllib.parse.urlsplit(url)
    if parsed.hostname in APP_HOSTS:
        headers.setdefault("Accept", "text/html")
        headers.setdefault("Sec-Fetch-Mode", "navigate")
        headers.setdefault("Host", parsed.netloc)
        url = urllib.parse.urlunsplit(
            ("http", "127.0.0.1:8000", parsed.path, parsed.query, parsed.fragment)
        )
    try:
        return opener.open(
            urllib.request.Request(url, data=data, headers=headers, method=method),
            timeout=20,
        )
    except urllib.error.HTTPError as response:
        return response


def record_keycloak_cookies(response):
    for header in response.headers.get_all("Set-Cookie", []):
        match = re.match(r"\s*([^=;,\s]+)=([^;]*)", header)
        if match:
            keycloak_cookies[match.group(1)] = match.group(2)


def keycloak_cookie_header():
    return "; ".join(f"{name}={value}" for name, value in keycloak_cookies.items())


def session_cookie(response):
    """Return the host-only session cookie (name=value) set on response, or "".

    The plugin sets a __Host- session cookie with no Max-Age attribute. During a
    callback it also clears the per-login cookie, which carries Max-Age, so it is
    skipped here.
    """
    for header in response.headers.get_all("Set-Cookie", []):
        if not header.startswith("__Host-") or "Max-Age=" in header:
            continue
        pair = header.split(";", 1)[0]
        name, _, value = pair.partition("=")
        if name and value:
            return header
    return ""


def session_cookie_pair(response):
    cookie = session_cookie(response)
    return cookie.split(";", 1)[0] if cookie else ""


def login_cookie_pair(response):
    """Return the browser-bound login cookie (name=value) set on response, or "".

    The plugin issues a __Host- login cookie carrying a positive Max-Age on the
    initial redirect to Keycloak; the callback must echo that cookie back so the
    plugin can match the callback to its pending transaction. Session cookies
    carry no Max-Age and clearing cookies carry Max-Age=0/-1, so both are
    skipped here.
    """
    for header in response.headers.get_all("Set-Cookie", []):
        if not header.startswith("__Host-"):
            continue
        max_age = re.search(r"Max-Age=(-?\d+)", header)
        if not max_age or int(max_age.group(1)) <= 0:
            continue
        pair = header.split(";", 1)[0]
        name, _, value = pair.partition("=")
        if name and value:
            return pair
    return ""


def query_of(url):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


CLAIMS_BLOCK = re.compile(
    r"Decoded token claims \(display only; not verified\)</h2>\s*<pre>(.*?)</pre>",
    re.DOTALL,
)


def access_token_jti(body):
    match = CLAIMS_BLOCK.search(body)
    require(match is not None, "page did not include decoded token claims")
    try:
        claims = json.loads(html.unescape(match.group(1)))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"decoded token claims were not valid JSON: {error}") from error
    jti = claims.get("jti")
    require(isinstance(jti, str) and jti, "access token claims did not include a nonempty jti")
    return jti


def session_cookie_expired(response, name):
    for header in response.headers.get_all("Set-Cookie", []):
        if not header.startswith(name + "="):
            continue
        max_age = re.search(r"Max-Age=(-?\d+)", header)
        if max_age and int(max_age.group(1)) <= 0:
            return True
    return False


def revoke_alice_sessions(keycloak_base):
    credentials = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "demo-admin",
            "password": "demo-admin-password",
        }
    ).encode()
    response = request(
        keycloak_base + "/realms/master/protocol/openid-connect/token",
        data=credentials,
    )
    require(response.status == 200, f"admin token request returned {response.status}")
    admin = json.loads(response.read().decode())
    token = admin.get("access_token")
    require(isinstance(token, str) and token, "admin token response did not include access_token")
    authorization = {"Authorization": "Bearer " + token}

    response = request(
        keycloak_base
        + "/admin/realms/demo/users?"
        + urllib.parse.urlencode({"username": "alice"}),
        headers=authorization,
    )
    require(response.status == 200, f"Alice lookup returned {response.status}")
    users = json.loads(response.read().decode())
    require(isinstance(users, list), "Alice lookup did not return a list")
    alice = next((user for user in users if user.get("username") == "alice"), None)
    require(alice is not None, "Alice was not found in the demo realm")
    user_id = alice.get("id")
    require(isinstance(user_id, str) and user_id, "Alice has no user id")

    response = request(
        keycloak_base + "/admin/realms/demo/users/" + urllib.parse.quote(user_id) + "/sessions",
        headers=authorization,
    )
    require(response.status == 200, f"Alice session lookup returned {response.status}")
    sessions = json.loads(response.read().decode())
    require(isinstance(sessions, list), "Alice session lookup did not return a list")
    require(sessions, "Alice had no Keycloak sessions to revoke")
    for session in sessions:
        session_id = session.get("id")
        require(isinstance(session_id, str) and session_id, "Keycloak session has no id")
        response = request(
            keycloak_base
            + "/admin/realms/demo/sessions/"
            + urllib.parse.quote(session_id, safe=""),
            headers=authorization,
            method="DELETE",
        )
        require(response.status in (200, 204), f"session delete returned {response.status}")


def check_token_lifecycle(session):
    protected = "http://helloworld1.localhost:8000/protected"
    response = request(protected, headers={"Cookie": session})
    body = response.read().decode()
    require(response.status == 200, f"lifecycle read returned {response.status}")
    first_jti = access_token_jti(body)

    time.sleep(11)
    response = request(protected, headers={"Cookie": session})
    body = response.read().decode()
    require(response.status == 200, f"renewed read returned {response.status}")
    second_jti = access_token_jti(body)
    require(first_jti != second_jti, "access token was not renewed after its lifetime elapsed")
    print("Access token renewed with a changed jti after its lifetime elapsed")

    revoke_alice_sessions("http://127.0.0.1:8081")
    print("Alice's demo Keycloak sessions were revoked through the Admin REST API")

    time.sleep(11)
    name = session.partition("=")[0]
    response = request(protected, headers={"Cookie": session})
    require(response.status == 303, f"revoked session should redirect; got {response.status}")
    require(session_cookie_expired(response, name), "revoked session cookie was not expired")
    print("Revoked session redirects to a fresh login and expires the session cookie")


def wait_for_stack():
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            keycloak = request(
                "http://127.0.0.1:8081/realms/demo/.well-known/openid-configuration"
            )
            app = request("http://helloworld1.localhost:8000/healthz")
            if keycloak.status == 200 and app.status == 200 and app.read().decode().strip() == "ok":
                print("Keycloak and Traefik are ready")
                return
        except urllib.error.URLError:
            pass
        time.sleep(2)
    raise RuntimeError("Timed out waiting for Keycloak and Traefik; inspect compose logs")


def authenticate_first_app():
    response = request("http://helloworld1.localhost:8000/protected?from=smoke")
    require(response.status == 303, f"initial request should redirect to login; got {response.status}")
    login_cookie = login_cookie_pair(response)
    require(login_cookie, "plugin did not issue a browser-bound login cookie")
    authorization_url = response.headers["Location"]
    require("/realms/demo/" in authorization_url, "redirect did not target demo realm")
    query = query_of(authorization_url)
    require(query.get("redirect_uri") == [CALLBACK_URLS["helloworld1.localhost"]],
            "redirect_uri was not the fixed registered callback")
    print("Unauthenticated request redirects to Keycloak with the fixed callback")

    response = request(authorization_url)
    require(response.status == 200, f"Keycloak login page returned {response.status}")
    record_keycloak_cookies(response)
    form = LoginForm()
    form.feed(response.read().decode())
    require(form.action, "Keycloak login form was not found")

    credentials = urllib.parse.urlencode(
        {"username": "alice", "password": "alice-password", "credentialId": ""}
    ).encode()
    response = request(
        form.action,
        data=credentials,
        headers={"Cookie": keycloak_cookie_header()},
    )
    record_keycloak_cookies(response)
    require(response.status in (302, 303), f"login failed with HTTP {response.status}")
    print("Alice can sign in to Keycloak")

    callback = response.headers["Location"]
    require("helloworld1.localhost:8000" in callback, "login did not return to helloworld1")
    response = request(callback, headers={"Cookie": login_cookie})
    require(response.status == 303, f"authorization callback returned {response.status}")
    cookie = session_cookie(response)
    require(cookie, "plugin did not issue a host-only __Host- session cookie")
    require("Secure" in cookie and "HttpOnly" in cookie and "Path=/" in cookie,
            "session cookie must be Secure, HttpOnly and Path=/")

    destination = response.headers["Location"]
    query = query_of(destination)
    require(query.get("from") == ["smoke"], "original request query was not preserved")
    require("code" not in query and "state" not in query, "authorization parameters were not removed")
    require(urllib.parse.urlsplit(destination).path == "/protected",
            "callback did not restore the original protected path")
    session = session_cookie_pair(response)
    response = request(destination, headers={"Cookie": session})
    body = response.read().decode()
    require(response.status == 200, f"authenticated app returned {response.status}")
    require("Authenticated user: <strong>alice</strong>" in body, "backend did not receive user header")
    require("Bearer token forwarded: true" in body, "backend did not receive bearer token")
    require("Decoded token claims (display only; not verified)" in body,
            "backend did not display decoded token claims")
    print("Callback sets a session; helloworld1 receives Alice and the bearer token")
    return session


def authenticate_second_app_with_sso():
    response = request("http://helloworld2.localhost:8000/protected")
    require(response.status == 303, f"helloworld2 should redirect to Keycloak; got {response.status}")
    login_cookie = login_cookie_pair(response)
    require(login_cookie, "helloworld2 did not issue a browser-bound login cookie")
    query = query_of(response.headers["Location"])
    require(query.get("redirect_uri") == [CALLBACK_URLS["helloworld2.localhost"]],
            "helloworld2 redirect_uri was not its fixed registered callback")
    response = request(response.headers["Location"], headers={"Cookie": keycloak_cookie_header()})
    record_keycloak_cookies(response)
    require(response.status in (302, 303),
            f"existing Keycloak login did not complete SSO; got HTTP {response.status}")
    require("helloworld2.localhost:8000" in response.headers.get("Location", ""),
            "SSO did not return to helloworld2")

    response = request(response.headers["Location"], headers={"Cookie": login_cookie})
    require(response.status == 303, f"helloworld2 callback returned {response.status}")
    session = session_cookie_pair(response)
    require(session, "helloworld2 did not receive its own session cookie")
    destination = response.headers["Location"]
    response = request(destination, headers={"Cookie": session})
    body = response.read().decode()
    require(response.status == 200, f"helloworld2 returned {response.status}")
    require("Authenticated user: <strong>alice</strong>" in body,
            "SSO did not authenticate Alice in helloworld2")
    require("Bearer token forwarded: true" in body, "helloworld2 did not receive bearer token")
    print("Keycloak SSO authenticates Alice in helloworld2 without another password")


def check_header_sanitization_protected(session):
    response = request(
        "http://helloworld1.localhost:8000/protected",
        headers={
            "Cookie": session,
            "X-Forwarded-User": "attacker",
            "Authorization": "Bearer attacker-token",
        },
    )
    body = response.read().decode()
    require(response.status == 200, f"protected path with session returned {response.status}")
    require("Authenticated user: <strong>alice</strong>" in body,
            "hostile X-Forwarded-User was not stripped and replaced")
    require("Bearer token forwarded: true" in body, "hostile Authorization was not stripped")
    require("Unable to decode token" not in body,
            "hostile Authorization bearer was forwarded instead of the validated token")
    print("Hostile X-Forwarded-User and Authorization are stripped on the protected path")


def check_header_sanitization_ignored():
    response = request(
        "http://helloworld1.localhost:8000/favicon.ico",
        headers={"X-Forwarded-User": "attacker", "Authorization": "Bearer attacker-token"},
    )
    body = response.read().decode()
    require(response.status == 200, f"ignored favicon path returned {response.status}")
    require("Authenticated user: <strong>not provided</strong>" in body,
            "ignored path did not strip X-Forwarded-User")
    require("Bearer token forwarded: false" in body, "ignored path did not strip Authorization")
    print("Hostile headers are stripped on the ignored path")


def main():
    wait_for_stack()
    health = request("http://helloworld1.localhost:8000/healthz")
    require(health.status == 200, f"ignored health check returned {health.status}")
    require(health.read().decode().strip() == "ok", "unexpected health check response")

    session = authenticate_first_app()
    authenticate_second_app_with_sso()

    check_header_sanitization_protected(session)
    check_header_sanitization_ignored()

    name = session.partition("=")[0]
    response = request("http://helloworld1.localhost:8000/protected",
                       headers={"Cookie": f"{name}=invalid"})
    require(response.status == 303, f"invalid session should redirect; got {response.status}")
    print("Invalid session is rejected")

    check_token_lifecycle(session)


if __name__ == "__main__":
    main()
