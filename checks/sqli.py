"""
checks/sqli.py - Detects SQL Injection.

Two techniques are used (detection only - we never read or change data):

1. Error-based: send characters that break SQL syntax (a quote, for example).
   If the page suddenly shows a database error message that was NOT there
   before, user input is probably being pasted straight into a SQL query.

2. Time-based (blind): send a payload that asks the database to wait a few
   seconds (SLEEP / WAITFOR / pg_sleep). If the response becomes slower by
   about that many seconds - twice in a row - the input reached the database.
"""

import re

from colorama import Fore, Style

from checks import make_finding

# Error messages that different databases print when a query is broken.
SQL_ERRORS = {
    "MySQL": [r"you have an error in your sql syntax", r"warning.*mysqli?_",
              r"mysql_fetch", r"valid mysql result", r"mysqlexception"],
    "PostgreSQL": [r"pg_query\(\)", r"postgresql.*error", r"unterminated quoted string",
                   r"syntax error at or near"],
    "MSSQL": [r"unclosed quotation mark", r"microsoft ole db provider for sql server",
              r"sqlserver jdbc driver", r"incorrect syntax near"],
    "Oracle": [r"ora-\d{5}", r"oracle error"],
    "SQLite": [r"sqlite3\.operationalerror", r"sqlite_error", r"sqlite/jdbcdriver",
               r"unrecognized token"],
}

# Characters that break the SQL syntax if the input is not escaped.
ERROR_PAYLOADS = ["'", '"', "')", "1'\""]

SLEEP_SECONDS = 5

# {v} = the parameter's normal value, {s} = seconds to sleep.
TIME_PAYLOADS = [
    ("{v}' AND (SELECT 1 FROM (SELECT SLEEP({s}))x)-- -", "MySQL"),
    ("{v} AND (SELECT 1 FROM (SELECT SLEEP({s}))x)", "MySQL"),
    ("{v}'; WAITFOR DELAY '0:0:{s}'--", "MSSQL"),
    ("{v}' AND 1=(SELECT 1 FROM PG_SLEEP({s}))-- -", "PostgreSQL"),
]

FIX = ("Use parameterised queries / prepared statements (or an ORM) instead of "
       "building SQL with string concatenation. Validate input and hide "
       "database error messages from users.")


def find_sql_error(text):
    """Return the database name if the text contains a known SQL error."""
    lowered = text.lower()
    for db, patterns in SQL_ERRORS.items():
        for pattern in patterns:
            if re.search(pattern, lowered):
                return db
    return None


def check_error_based(client, target, param, baseline_text):
    """Try each error payload. Returns a finding or None."""
    original = target["params"][param]
    for payload in ERROR_PAYLOADS:
        resp = client.send(target, param, original + payload)
        if resp is None:
            continue
        db = find_sql_error(resp.text)
        # Only report if the error is new (not already on the normal page).
        if db and find_sql_error(baseline_text) is None:
            return make_finding(
                "SQL Injection (error-based)", "High", target["url"], target["method"],
                param, original + payload, f"{db} error message appeared in the response", FIX)
    return None


def check_time_based(client, target, param, baseline_time):
    """Try each sleep payload. Returns a finding or None."""
    original = target["params"][param]
    timeout = client.timeout + SLEEP_SECONDS
    for template, db in TIME_PAYLOADS:
        payload = template.format(v=original, s=SLEEP_SECONDS)
        delays = []
        for _ in range(2):  # send twice to avoid false positives from a slow network
            resp = client.send(target, param, payload, timeout=timeout)
            if resp is None:
                break
            delays.append(resp.elapsed.total_seconds())
            if delays[-1] < baseline_time + SLEEP_SECONDS - 0.5:
                break
        if len(delays) == 2 and min(delays) >= baseline_time + SLEEP_SECONDS - 0.5:
            evidence = (f"Response took {min(delays):.1f}s with the payload vs "
                        f"{baseline_time:.1f}s normally ({db} sleep function)")
            return make_finding("SQL Injection (time-based blind)", "High", target["url"],
                                target["method"], param, payload, evidence, FIX)
    return None


def run(client, targets):
    """Test every injectable parameter of every target."""
    findings = []
    for target in targets:
        # Baseline: the normal response, used for comparison.
        baseline = client.request(target["method"], target["url"], target["params"])
        if baseline is None:
            continue
        baseline_time = baseline.elapsed.total_seconds()

        for param in target["injectable"]:
            print(f"  {Fore.CYAN}[sqli]{Style.RESET_ALL} {target['method'].upper()} {target['url']} -> {param}")
            finding = check_error_based(client, target, param, baseline.text)
            if finding is None:
                finding = check_time_based(client, target, param, baseline_time)
            if finding:
                findings.append(finding)
                print(f"    {Fore.RED}[!] {finding['vulnerability']} in '{param}'{Style.RESET_ALL}")
    return findings
