"""
checks/csrf.py - Detects missing Cross-Site Request Forgery (CSRF) protection.

This check sends no attack requests. It only looks at what the crawler saw:

1. POST forms without a hidden anti-CSRF token field. Without a secret,
   unpredictable token, another website can make the victim's browser submit
   the form.
2. GET forms that contain a password field (e.g. "change password") and no
   token. Sensitive
   actions over GET can be triggered by a simple link or <img> tag.
3. Cookies without the SameSite attribute (or SameSite=None without Secure).
   SameSite stops the browser from sending the cookie on cross-site requests.
"""

import re

from colorama import Fore, Style

from checks import make_finding

# Common names used by frameworks for anti-CSRF tokens
# (Django: csrfmiddlewaretoken, Rails: authenticity_token, DVWA: user_token, ...).
TOKEN_PATTERN = re.compile(r"csrf|xsrf|token|nonce|authenticity|requestverification", re.I)

FORM_FIX = ("Add a random, per-session anti-CSRF token to every state-changing form "
            "and verify it on the server. Use POST (not GET) for actions that change data.")
COOKIE_FIX = ("Set the SameSite attribute on cookies (SameSite=Lax or Strict). "
              "If SameSite=None is required, the cookie must also be Secure.")


def check_forms(pages):
    findings = []
    seen = set()
    for page in pages:
        for form in page["forms"]:
            key = (form["method"], form["action"])
            if key in seen:
                continue
            seen.add(key)
            names = ", ".join(i["name"] for i in form["inputs"]) or "(no fields)"
            has_token = any(i["type"] == "hidden" and TOKEN_PATTERN.search(i["name"])
                            for i in form["inputs"])
            if has_token:
                continue  # the form is protected by a token

            if form["method"] == "post":
                findings.append(make_finding(
                    "CSRF (no anti-CSRF token)", "Medium", form["action"], "post",
                    names, "N/A (passive check)",
                    f"POST form on {form['page']} has no hidden token field", FORM_FIX))

            elif any(i["type"] == "password" for i in form["inputs"]):
                findings.append(make_finding(
                    "CSRF (sensitive action via GET)", "Medium", form["action"], "get",
                    names, "N/A (passive check)",
                    f"GET form on {form['page']} sends a password field in the URL", FORM_FIX))
    return findings


def check_cookies(client):
    findings = []
    seen = set()
    for url, header in client.set_cookie_headers:
        name = header.split("=", 1)[0].strip()
        if name in seen:
            continue
        seen.add(name)
        attributes = header.lower()

        if "samesite" not in attributes:
            problem = "Cookie has no SameSite attribute"
        elif "samesite=none" in attributes.replace(" ", "") and "secure" not in attributes:
            problem = "Cookie uses SameSite=None without Secure"
        else:
            continue
        findings.append(make_finding(
            "CSRF (cookie without SameSite)", "Low", url, "get", f"Cookie: {name}",
            "N/A (passive check)", problem, COOKIE_FIX))
    return findings


def run(client, pages):
    """Run both passive CSRF checks."""
    print(f"  {Fore.CYAN}[csrf]{Style.RESET_ALL} analysing {sum(len(p['forms']) for p in pages)} forms "
          f"and {len(client.set_cookie_headers)} Set-Cookie headers")
    findings = check_forms(pages) + check_cookies(client)
    for f in findings:
        print(f"    {Fore.YELLOW}[!] {f['vulnerability']} at {f['url']}{Style.RESET_ALL}")
    return findings
