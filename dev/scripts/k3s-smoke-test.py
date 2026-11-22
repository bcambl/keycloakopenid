#!/usr/bin/env python3
"""Exercise the k3s path-based demo: Keycloak at /auth, apps at /helloworld1 and /helloworld2."""

import argparse
import html
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser


APPS = ("helloworld1", "helloworld2")
CLIENT_IDS = {
    "per-app": {"helloworld1": "helloworld1", "helloworld2": "helloworld2"},
    "shared": {"helloworld1": "helloworld-shared", "helloworld2": "helloworld-shared"},
}
# Each client registers one fixed callback. The plugin sends this exact URI as
# redirect_uri regardless of the requested path, then restores the path.
CALLBACK_PATHS = {
    "per-app": {"helloworld1": "/helloworld1/callback", "helloworld2": "/helloworld2/callback"},
    "shared": {"helloworld1": "/callback", "helloworld2": "/callback"},
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


# The demo uses a self-signed certificate, so verification is disabled on purpose.
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), NoRedirect())
keycloak_cookies = {}


def request(url, data=None, headers=None, method=None):
    headers = dict(headers or {})
    if not urllib.parse.urlsplit(url).path.startswith("/auth/"):
        headers.setdefault("Accept", "text/html")
        headers.setdefault("Sec-Fetch-Mode", "navigate")
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


def admin_access_token(keycloak_base):
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
    return token


def realm_access_token_lifespan(keycloak_base):
    token = admin_access_token(keycloak_base)
    response = request(
        keycloak_base + "/admin/realms/demo",
        headers={"Authorization": "Bearer " + token},
    )
    require(response.status == 200, f"realm lookup returned {response.status}")
    realm = json.loads(response.read().decode())
    lifespan = realm.get("accessTokenLifespan")
    require(isinstance(lifespan, int) and lifespan > 0, "realm has no valid accessTokenLifespan")
    require(
        lifespan == 10,
        f"demo realm accessTokenLifespan is {lifespan}, not 10; recreate Keycloak so the realm is re-imported",
    )
    return lifespan


def revoke_alice_sessions(keycloak_base):
    token = admin_access_token(keycloak_base)
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


class Demo:
    def __init__(self, host, mode):
        self.base = f"https://{host}"
        self.mode = mode

    def url(self, path):
        return self.base + path

    def callback_url(self, app):
        return self.base + CALLBACK_PATHS[self.mode][app]

    def expect_keycloak_redirect(self, response, app):
        require(response.status == 303, f"{app} should redirect to Keycloak; got {response.status}")
        location = response.headers["Location"]
        require(location.startswith(self.url("/auth/realms/demo/")),
                f"{app} redirect did not target the demo realm at /auth: {location}")
        query = query_of(location)
        expected_client = CLIENT_IDS[self.mode][app]
        require(query.get("client_id") == [expected_client],
                f"{app} used client {query.get('client_id')}, expected {expected_client}")
        require(query.get("redirect_uri") == [self.callback_url(app)],
                f"{app} redirect_uri was not its fixed registered callback: {query.get('redirect_uri')}")
        return location

    def wait_until_ready(self):
        deadline = time.monotonic() + 300
        last_error = "no response"
        while time.monotonic() < deadline:
            try:
                keycloak = request(self.url("/auth/realms/demo/.well-known/openid-configuration"))
                health = request(self.url("/helloworld1/healthz"))
                protected = request(self.url("/helloworld1/"))
                location = protected.headers.get("Location", "")
                client = query_of(location).get("client_id", [""])[0]
                if (keycloak.status == 200 and health.status == 200 and protected.status == 303
                        and client == CLIENT_IDS[self.mode]["helloworld1"]):
                    print(f"Keycloak, Traefik and the {self.mode} routes are ready")
                    return
                last_error = (f"keycloak={keycloak.status} health={health.status} "
                              f"protected={protected.status} client={client or '-'}")
            except (urllib.error.URLError, OSError) as error:
                last_error = str(error)
            time.sleep(3)
        raise RuntimeError(f"Timed out waiting for the {self.mode} demo ({last_error}); run make vm-status")

    def check_health_bypass(self):
        for app in APPS:
            response = request(self.url(f"/{app}/healthz"))
            require(response.status == 200 and response.read().decode().strip() == "ok",
                    f"/{app}/healthz should bypass auth; got {response.status}")
        print("Health paths bypass authentication on both apps")

    def login(self, app):
        target = f"/{app}/protected?from=smoke"
        response = request(self.url(target))
        login_cookie = login_cookie_pair(response)
        require(login_cookie, f"/{app} did not issue a browser-bound login cookie")
        authorization_url = self.expect_keycloak_redirect(response, app)
        print(f"Unauthenticated /{app} request redirects to Keycloak with the fixed callback")

        response = request(authorization_url)
        require(response.status == 200, f"Keycloak login page returned {response.status}")
        record_keycloak_cookies(response)
        form = LoginForm()
        form.feed(response.read().decode())
        require(form.action, "Keycloak login form was not found")

        credentials = urllib.parse.urlencode(
            {"username": "alice", "password": "alice-password", "credentialId": ""}
        ).encode()
        response = request(form.action, data=credentials, headers={"Cookie": keycloak_cookie_header()})
        record_keycloak_cookies(response)
        require(response.status in (302, 303), f"login failed with HTTP {response.status}")
        print("Alice signs in to Keycloak")
        return self.finish_callback(response.headers["Location"], app, target, login_cookie)

    def sso(self, app):
        target = f"/{app}/protected"
        response = request(self.url(target))
        login_cookie = login_cookie_pair(response)
        require(login_cookie, f"/{app} did not issue a browser-bound login cookie")
        authorization_url = self.expect_keycloak_redirect(response, app)
        response = request(authorization_url, headers={"Cookie": keycloak_cookie_header()})
        record_keycloak_cookies(response)
        require(response.status in (302, 303),
                f"existing Keycloak login did not complete SSO for {app}; got HTTP {response.status}")
        return self.finish_callback(response.headers["Location"], app, target, login_cookie)

    def finish_callback(self, callback, app, target, login_cookie):
        require(callback.startswith(self.callback_url(app) + "?"),
                f"Keycloak did not return to the fixed callback {self.callback_url(app)}: {callback}")
        response = request(callback, headers={"Cookie": login_cookie})
        require(response.status == 303, f"{app} callback returned {response.status}")
        cookie = session_cookie(response)
        require(cookie, f"{app} did not issue a host-only __Host- session cookie")
        require("Secure" in cookie and "HttpOnly" in cookie and "Path=/" in cookie,
                f"{app} did not issue a Secure, HttpOnly session cookie with Path=/")
        destination = response.headers["Location"]
        query = query_of(destination)
        require("code" not in query and "state" not in query, "authorization parameters were not removed")
        expected = urllib.parse.urlsplit(self.url(target))
        actual = urllib.parse.urlsplit(destination)
        require(actual.path == expected.path,
                f"callback did not restore the original path {expected.path}: {destination}")
        require(actual.query == expected.query,
                f"callback did not restore the original query {expected.query!r}: {destination}")
        session = session_cookie_pair(response)
        self.expect_app(app, session)
        return session

    def expect_app(self, app, session):
        response = request(self.url(f"/{app}/protected"), headers={"Cookie": session})
        body = response.read().decode()
        require(response.status == 200, f"/{app} with a valid session returned {response.status}")
        require(f"Hello from {app}" in body, f"/{app} was not routed to the {app} backend")
        require("Authenticated user: <strong>alice</strong>" in body, f"{app} did not receive X-Forwarded-User")
        require("Bearer token forwarded: true" in body, f"{app} did not receive the bearer token")
        require(session_cookie(response) == "", f"{app} unexpectedly replaced the session cookie")

    def check_header_sanitization(self, app, session):
        response = request(
            self.url(f"/{app}/protected"),
            headers={
                "Cookie": session,
                "X-Forwarded-User": "attacker",
                "Authorization": "Bearer attacker-token",
            },
        )
        body = response.read().decode()
        require(response.status == 200, f"/{app}/protected with session returned {response.status}")
        require("Authenticated user: <strong>alice</strong>" in body,
                f"/{app} did not strip and replace hostile X-Forwarded-User")
        require("Bearer token forwarded: true" in body, f"/{app} did not strip hostile Authorization")
        require("Unable to decode token" not in body,
                f"/{app} forwarded the hostile bearer token instead of the validated one")

        response = request(
            self.url(f"/{app}/favicon.ico"),
            headers={"X-Forwarded-User": "attacker", "Authorization": "Bearer attacker-token"},
        )
        body = response.read().decode()
        require(response.status == 200, f"/{app}/favicon.ico returned {response.status}")
        require("Authenticated user: <strong>not provided</strong>" in body,
                f"/{app} ignored path did not strip X-Forwarded-User")
        require("Bearer token forwarded: false" in body,
                f"/{app} ignored path did not strip Authorization")
        print(f"Hostile X-Forwarded-User and Authorization are stripped on /{app} protected and ignored paths")

    def check_invalid_session(self, name):
        response = request(self.url("/helloworld1/protected"),
                           headers={"Cookie": f"{name}=invalid"})
        self.expect_keycloak_redirect(response, "helloworld1")
        print("An invalid session cookie redirects to Keycloak")

    def check_token_lifecycle(self, session):
        realm_access_token_lifespan(self.base + "/auth")
        protected = self.url("/helloworld1/protected")
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

        revoke_alice_sessions(self.base + "/auth")
        print("Alice's demo Keycloak sessions were revoked through the Admin REST API")

        time.sleep(11)
        name = session.partition("=")[0]
        response = request(protected, headers={"Cookie": session})
        require(response.status == 303, f"revoked session should redirect; got {response.status}")
        require(session_cookie_expired(response, name), "revoked session cookie was not expired")
        print("Revoked session redirects to a fresh login and expires the session cookie")

    def run_per_app(self):
        first = self.login("helloworld1")
        print("helloworld1 receives Alice and the bearer token")
        first_name = first.partition("=")[0]

        second = self.sso("helloworld2")
        second_name = second.partition("=")[0]
        require(first_name != second_name,
                "distinct clients must issue distinct __Host- cookie names")
        print("helloworld2 completes SSO without a password and issues its own __Host- cookie")

        self.expect_app("helloworld1", first)
        print("helloworld1's session survives helloworld2's login (distinct-client cookie isolation)")

        response = request(self.url("/helloworld1/protected"), headers={"Cookie": second})
        self.expect_keycloak_redirect(response, "helloworld1")
        print("helloworld2's cookie is unknown to helloworld1 and forces a fresh login")

        self.check_header_sanitization("helloworld1", first)
        self.check_invalid_session(first_name)
        self.check_token_lifecycle(first)

    def run_shared(self):
        session = self.login("helloworld1")
        print("helloworld1 receives Alice and the bearer token")
        self.expect_app("helloworld2", session)
        self.expect_app("helloworld1", session)
        print("One session cookie authenticates both paths across two separate middlewares sharing one client")

        self.check_header_sanitization("helloworld1", session)
        self.check_invalid_session(session.partition("=")[0])
        self.check_token_lifecycle(session)

    def run(self):
        self.wait_until_ready()
        self.check_health_bypass()
        if self.mode == "per-app":
            self.run_per_app()
        else:
            self.run_shared()
        print(f"{self.mode} smoke test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=sorted(CLIENT_IDS), required=True)
    parser.add_argument("--host", default=os.environ.get("VM_HOST"),
                        help="demo host name or IP (defaults to $VM_HOST)")
    args = parser.parse_args()
    if not args.host:
        parser.error("--host or VM_HOST is required")
    try:
        Demo(args.host, args.mode).run()
    except RuntimeError as error:
        print(f"FAILED: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
