"""A tiny JSON-over-HTTPS helper built on the standard library, with retries and paging.
Every call this tool makes to Google or Microsoft goes through here, and only GET is used
for data (POST is used only to sign in)."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "ai-readiness-check/0.1 (read-only)"


class ApiError(Exception):
    def __init__(self, status, message, url=""):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.url = url


def _send(req, retries):
    delay = 2
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = e.headers.get("Retry-After")
                time.sleep(float(wait) if wait and wait.isdigit() else delay)
                delay *= 2
                continue
            try:
                err = json.loads(body).get("error", body)
                if isinstance(err, dict):
                    err = err.get("message") or err.get("code") or str(err)
            except ValueError:
                err = body[:300]
            raise ApiError(e.code, str(err), req.full_url) from None
        except urllib.error.URLError as e:
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise ApiError(0, str(e.reason), req.full_url) from None


def get(url, token, params=None, headers=None, retries=4):
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    h = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": USER_AGENT}
    h.update(headers or {})
    return _send(urllib.request.Request(url, headers=h, method="GET"), retries)


def post_form(url, data, retries=2):
    """Sign-in only: OAuth device code and token endpoints."""
    body = urllib.parse.urlencode(data).encode()
    h = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
         "User-Agent": USER_AGENT}
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        # OAuth endpoints answer 400 with a JSON body while sign-in is pending or refused.
        raw = e.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            return {"error": f"http_{e.code}", "error_description": raw[:300]}
    except urllib.error.URLError as e:
        return {"error": "network", "error_description": str(e.reason)}


def google_pages(url, token, params, key, limit=None):
    """Yield items across Google 'nextPageToken' pages."""
    params = dict(params or {})
    seen = 0
    while True:
        data = get(url, token, params)
        for item in data.get(key, []) or []:
            yield item
            seen += 1
            if limit and seen >= limit:
                return
        tok = data.get("nextPageToken")
        if not tok:
            return
        params["pageToken"] = tok


def graph_pages(url, token, params=None, headers=None, limit=None):
    """Yield items across Microsoft Graph '@odata.nextLink' pages."""
    seen = 0
    data = get(url, token, params, headers)
    while True:
        for item in data.get("value", []) or []:
            yield item
            seen += 1
            if limit and seen >= limit:
                return
        nxt = data.get("@odata.nextLink")
        if not nxt:
            return
        data = get(nxt, token, None, headers)
