"""
checks/xss.py - Detects reflected Cross-Site Scripting (XSS).

Idea: send a harmless, unique marker wrapped in HTML special characters,
for example   '"><vsxa1b2c3d4>
If the page sends it back exactly as-is (the < and > are NOT converted to
&lt; and &gt;), the browser would treat our text as real HTML. That means a
real attacker could inject a <script> tag the same way.

We never send real JavaScript - the marker is a fake tag that does nothing.
"""

import uuid

from colorama import Fore, Style

from checks import make_finding

FIX = ("HTML-encode all user input before writing it into a page (use your "
       "template engine's auto-escaping), validate input, and add a "
       "Content-Security-Policy header.")


def run(client, targets):
    """Test every injectable parameter of every target for reflected XSS."""
    findings = []
    for target in targets:
        for param in target["injectable"]:
            print(f"  {Fore.CYAN}[xss]{Style.RESET_ALL} {target['method'].upper()} {target['url']} -> {param}")

            # A new random marker each time, so we know exactly which input was reflected.
            marker = "vsx" + uuid.uuid4().hex[:8]
            tag = f"<{marker}>"
            payload = f"'\">{tag}"

            resp = client.send(target, param, payload)
            if resp is None:
                continue

            if tag in resp.text:
                findings.append(make_finding(
                    "Cross-Site Scripting (reflected)", "High", target["url"], target["method"],
                    param, payload, f"Marker {tag} was reflected without HTML encoding", FIX))
                print(f"    {Fore.RED}[!] Reflected XSS in '{param}'{Style.RESET_ALL}")
            # If only the marker text (without < >) comes back, the site is
            # escaping it correctly, so we do not report anything.
    return findings
