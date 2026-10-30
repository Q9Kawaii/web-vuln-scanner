"""
crawler.py - Discovers pages, links, forms and URL parameters on the target site.

It contains two classes:
  * HttpClient - a small wrapper around requests.Session that adds a timeout,
                 a polite delay between requests, and remembers every
                 Set-Cookie header (the CSRF check needs them later).
  * Crawler    - a breadth-first crawler that stays on the same domain and
                 turns what it finds into "targets" (things we can test).
"""

import time
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse, urldefrag, parse_qs

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

# Files that are not HTML pages - no point downloading them.
SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".js", ".pdf",
    ".zip", ".gz", ".rar", ".mp3", ".mp4", ".avi", ".woff", ".woff2", ".ttf", ".exe",
)

# URLs containing these words are never visited or submitted. Logging out would
# end our session, and "setup.php" in DVWA resets the whole database.
DEFAULT_EXCLUDES = ["logout", "logoff", "signout", "setup.php"]

# Input types we never inject payloads into (they are buttons, not data).
NON_INJECTABLE_TYPES = ("submit", "button", "image", "reset", "file")


class HttpClient:
    """Sends HTTP requests with a timeout and a delay between each request."""

    def __init__(self, timeout=10, delay=0.5, cookies=None):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "VulnScan/1.0 (educational scanner)"
        self.timeout = timeout
        self.delay = delay
        self.request_count = 0
        self.set_cookie_headers = []  # list of (url, raw Set-Cookie header)

        # Optional cookies, e.g. "PHPSESSID=abc; security=low" (used to scan
        # pages behind a login, such as DVWA).
        if cookies:
            for part in cookies.split(";"):
                if "=" in part:
                    name, value = part.split("=", 1)
                    self.session.cookies.set(name.strip(), value.strip())

    def request(self, method, url, params=None, timeout=None):
        """Send a GET or POST request. Returns the Response, or None on error."""
        time.sleep(self.delay)  # be polite: don't flood the server
        self.request_count += 1
        try:
            if method == "post":
                resp = self.session.post(url, data=params, timeout=timeout or self.timeout)
            else:
                resp = self.session.get(url, params=params, timeout=timeout or self.timeout)
        except requests.RequestException:
            return None
        self._remember_cookies(resp)
        return resp

    def send(self, target, param, payload, timeout=None):
        """Send a target's request with one parameter replaced by a payload."""
        data = dict(target["params"])
        data[param] = payload
        return self.request(target["method"], target["url"], data, timeout)

    def _remember_cookies(self, resp):
        """Store raw Set-Cookie headers (including ones from redirects)."""
        for r in list(resp.history) + [resp]:
            try:
                headers = r.raw.headers.getlist("Set-Cookie")
            except AttributeError:
                headers = [r.headers["Set-Cookie"]] if "Set-Cookie" in r.headers else []
            for header in headers:
                self.set_cookie_headers.append((r.url, header))


class Crawler:
    """Breadth-first crawler limited to one domain and a maximum depth."""

    def __init__(self, client, start_url, max_depth=2, max_pages=50, excludes=None):
        self.client = client
        self.start_url = urldefrag(start_url)[0]
        self.domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.excludes = [e.lower() for e in (excludes or DEFAULT_EXCLUDES)]

    def is_allowed(self, url):
        """Only http(s), same domain, not a static file, not an excluded URL."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or parsed.netloc != self.domain:
            return False
        if parsed.path.lower().endswith(SKIP_EXTENSIONS):
            return False
        return not any(word in url.lower() for word in self.excludes)

    def crawl(self):
        """Visit pages starting at start_url. Returns a list of page dicts."""
        queue = deque([(self.start_url, 0)])
        visited = set()
        pages = []

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            resp = self.client.request("get", url)
            if resp is None or "html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            forms = self.extract_forms(soup, resp.url)
            pages.append({"url": resp.url, "forms": forms})
            print(f"  {Fore.CYAN}[crawl]{Style.RESET_ALL} depth={depth} forms={len(forms)} {resp.url}")

            # Follow links only while we are below the depth limit.
            if depth < self.max_depth:
                for link in self.extract_links(soup, resp.url):
                    if link not in visited:
                        queue.append((link, depth + 1))

        return pages

    def extract_links(self, soup, page_url):
        """Return absolute, allowed URLs from all <a href> tags on the page."""
        links = []
        for a in soup.find_all("a", href=True):
            link = urldefrag(urljoin(page_url, a["href"]))[0]
            if self.is_allowed(link) and link not in links:
                links.append(link)
        return links

    def extract_forms(self, soup, page_url):
        """Return each form's action URL, method and input fields."""
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            method = (form.get("method") or "get").lower()
            inputs = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                if field.name == "select":
                    option = field.find("option")
                    ftype = "select"
                    value = option.get("value", option.text) if option else ""
                elif field.name == "textarea":
                    ftype = "textarea"
                    value = field.text
                else:
                    ftype = (field.get("type") or "text").lower()
                    value = field.get("value", "")
                inputs.append({"name": name, "type": ftype, "value": value})
            forms.append({"action": action, "method": method, "inputs": inputs, "page": page_url})
        return forms

    def build_targets(self, pages):
        """
        Turn pages into a list of testable targets. A target is one request
        (method + URL + parameters) and the list of parameters we may inject into.
        Both URL query strings (?id=1) and forms become targets.
        """
        targets = []
        seen = set()

        def add(method, url, params, injectable, source):
            key = (method, url, tuple(sorted(params)))
            if injectable and key not in seen:
                seen.add(key)
                targets.append({"method": method, "url": url, "params": params,
                                "injectable": injectable, "source": source})

        for page in pages:
            # 1) Parameters in the page URL, e.g. artists.php?artist=1
            parsed = urlparse(page["url"])
            if parsed.query:
                params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
                base = urlunparse(parsed._replace(query=""))
                add("get", base, params, list(params), page["url"])

            # 2) Form fields
            for form in page["forms"]:
                if not self.is_allowed(form["action"]):
                    continue
                params = {}
                injectable = []
                for field in form["inputs"]:
                    params[field["name"]] = field["value"] or self.default_value(field["type"])
                    if field["type"] not in NON_INJECTABLE_TYPES:
                        injectable.append(field["name"])
                add(form["method"], form["action"], params, injectable, page["url"])

        return targets

    @staticmethod
    def default_value(field_type):
        """A harmless value for empty fields so the form looks 'normal'."""
        if field_type == "email":
            return "test@example.com"
        return "1"  # "1" works for both numeric IDs and text fields
