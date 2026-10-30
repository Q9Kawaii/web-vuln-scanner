"""
checks package - one module per vulnerability type.

Every check module has a run(...) function that returns a list of "findings".
A finding is a plain dict so it is easy to print, save as JSON and show in HTML.
"""


def make_finding(vuln, severity, url, method, param, payload, evidence, fix):
    """Build one finding dict with the same keys for every check."""
    return {
        "vulnerability": vuln,
        "severity": severity,  # High / Medium / Low
        "url": url,
        "method": method.upper(),
        "parameter": param,
        "payload": payload,
        "evidence": evidence,
        "fix": fix,
    }
