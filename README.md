# VulnScan — Simple Web Vulnerability Scanner

A Python command-line tool that crawls a website and **detects** three common web vulnerabilities:

| Vulnerability | How VulnScan detects it |
|---|---|
| **SQL Injection (SQLi)** | Error-based (database error messages appear) and time-based blind (response slows down after a `SLEEP` payload) |
| **Cross-Site Scripting (XSS)** | Sends a unique harmless marker such as `'"><vsxa1b2c3d4>` and checks whether it comes back **unescaped** |
| **Cross-Site Request Forgery (CSRF)** | POST forms with no anti-CSRF token, password forms sent over GET, and cookies without the `SameSite` attribute |

It only **detects** these problems. It never extracts data, logs in by force, or runs real attack code.

> ⚠️ **Disclaimer: for education only.** Only scan websites you own or have written permission to test. Scanning other systems without permission may be illegal (for example under the IT Act 2000 in India or the Computer Misuse Act in the UK). The authors take no responsibility for misuse.

---

## Project structure

```
vulnscan/
├── scanner.py        # CLI entry point: arguments, consent prompt, runs everything
├── crawler.py        # HttpClient (timeout + delay) and Crawler (links, forms, params)
├── checks/
│   ├── __init__.py   # make_finding() helper shared by all checks
│   ├── sqli.py       # SQL Injection: error-based + time-based
│   ├── xss.py        # Reflected XSS: unique unescaped marker
│   └── csrf.py       # CSRF: missing tokens + cookie SameSite
├── report.py         # Terminal summary + JSON + HTML (Jinja2) report
├── requirements.txt
└── README.md
```

## How it works (scan flow)

1. **Consent:** the tool shows a warning, and you must type `yes` to continue.
2. **Crawl:** starting at the given URL, it follows `<a href>` links breadth-first, up to `--depth` levels. It stays on the same domain and skips images, CSS, JS and `logout`/`setup.php` links.
3. **Build targets:** every URL query parameter (`?id=1`) and every form field becomes something to test.
4. **Run checks:** SQLi and XSS send one modified request per parameter. CSRF is passive and only looks at the forms and cookies that were already collected.
5. **Report:** findings are printed in colour and saved as `<name>.html` and `<name>.json`. Each finding has a URL, parameter, payload, severity, evidence and fix.

All requests have a **timeout** (`--timeout`, default 10 s) and a **delay** between them (`--delay`, default 0.5 s), so the scanner does not overload the server.

---

## Installation

Requires Python 3.8+.

```bash
cd vulnscan
python -m venv venv
# Windows: venv\Scripts\activate     Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py -u <URL> [--depth N] [--checks sqli,xss,csrf] [--report NAME]
```

| Option | Meaning | Default |
|---|---|---|
| `-u, --url` | Start URL (required) | – |
| `--depth` | How many links deep to crawl | `2` |
| `--checks` | Comma-separated: `sqli`, `xss`, `csrf` | all three |
| `--report` | Report file name without extension | `scan_report` |
| `--max-pages` | Stop crawling after this many pages | `50` |
| `--delay` | Seconds between requests | `0.5` |
| `--timeout` | Request timeout in seconds | `10` |
| `--cookie` | Session cookies for pages behind a login, e.g. `"PHPSESSID=abc; security=low"` | none |
| `--exclude` | Skip URLs containing these words | `logout,logoff,signout,setup.php` |

Examples:

```bash
# Full scan
python scanner.py -u http://testphp.vulnweb.com/ --depth 2 --report testphp

# Only XSS and CSRF, shallow crawl
python scanner.py -u http://localhost/myapp/ --depth 1 --checks xss,csrf
```

Sample terminal output:

```
[1] Crawling http://127.0.0.1:8765/ (depth 2)
  [crawl] depth=0 forms=2 http://127.0.0.1:8765/
  [crawl] depth=1 forms=0 http://127.0.0.1:8765/user?id=1
...
=== Scan summary: 5 finding(s) ===
[High] SQL Injection (error-based)
    URL:       GET http://127.0.0.1:8765/user
    Parameter: id
    Payload:   1'
[High] Cross-Site Scripting (reflected)
    URL:       GET http://127.0.0.1:8765/search
    Parameter: q
    Payload:   '"><vsx1daed258>
[Medium] CSRF (no anti-CSRF token)
    URL:       POST http://127.0.0.1:8765/comment
...
Reports saved: scan_report.html, scan_report.json
```

---

## Tools used and why

| Tool | Why we used it |
|---|---|
| **Python** | Easy to read, has good HTTP and HTML libraries, and is widely taught |
| **requests** | Simple API for GET/POST, sessions (cookies), timeouts and response timing (`resp.elapsed`, which the time-based SQLi check needs) |
| **BeautifulSoup (bs4)** | Parses real-world, messy HTML so we can find `<a>` links and `<form>`/`<input>` fields |
| **argparse** | Built into Python. It gives us `-u`, `--depth` and so on, plus automatic `--help` |
| **Jinja2** | Template engine for the HTML report. Its **autoescaping** stops our own XSS payloads from running when the report is opened |
| **colorama** | Coloured terminal output that also works on Windows |
| **json** (built-in) | Machine-readable report that other tools can use |

## Alternatives and why we did not use them

| Tool | What it is | Why we built our own instead |
|---|---|---|
| **OWASP ZAP** | Full open-source proxy and scanner with a GUI | Very powerful but large. Using it teaches the tool, not *how* detection works. Our goal was to understand and explain each step. |
| **sqlmap** | Automated SQL injection detection **and exploitation** | Only covers SQLi and goes far beyond detection (dumping databases, OS shells). The project scope is detection only. |
| **Burp Suite** | Industry-standard intercepting proxy. The scanner is in the paid Pro version | The paid scanner is closed-source, and Burp is mainly a manual testing tool. |
| **Nikto** | Web server scanner (outdated software, dangerous files, misconfigurations) | Checks server configuration against a known-issues database. It does not test parameters for SQLi/XSS the way we do. |

These tools are far more complete and accurate. VulnScan is a **learning project** that shows the core ideas in about 500 readable lines.

## Black-box approach

VulnScan is a **black-box** scanner. It has no access to source code, the database or the server. It only sees what any visitor sees, which is HTTP requests and responses. It infers vulnerabilities from the application's **behaviour**:

- a database error appears → input probably reaches a SQL query (SQLi)
- the response is 5 seconds slower after a `SLEEP(5)` payload → input is executed by the database (blind SQLi)
- our `<marker>` comes back unescaped → input is written into HTML without encoding (XSS)
- a POST form has no hidden secret token → requests can be forged (CSRF)

This is the opposite of **white-box** testing (reviewing source code, static analysis). Black-box testing is realistic because it is what an attacker can do, but it can miss bugs and can produce false positives.

---

## Testing

### 1. testphp.vulnweb.com (public, intentionally vulnerable)

`http://testphp.vulnweb.com/` is a deliberately vulnerable PHP site run by Acunetix so people can test scanners on it.

```bash
python scanner.py -u http://testphp.vulnweb.com/ --depth 2 --max-pages 30 --report testphp
```

**Expected findings.** These are the site's publicly documented weaknesses. Your run may differ depending on crawl depth and the site's current state.

| Expected finding | Where |
|---|---|
| SQLi (error-based, MySQL) | `listproducts.php?cat=`, `artists.php?artist=`, `product.php?pic=` |
| Reflected XSS | `search.php` (POST field `searchFor`) |
| CSRF – no token | `search.php` search form, `guestbook.php`, `userinfo.php` login form (POST) |
| Cookie without SameSite | Session cookies set by the site, if any are issued during the crawl |

> **My results:** *(paste your own summary or screenshot of `testphp.html` here)*

### 2. DVWA (Damn Vulnerable Web Application, local)

DVWA runs locally, so you are scanning your own machine, which is safe and legal.

```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```

1. Open `http://localhost:8080`, log in as `admin` / `password`, and click **Create / Reset Database** on the setup page.
2. Go to **DVWA Security** and set the level to **Low**.
3. Copy your `PHPSESSID` cookie from the browser (DevTools → Application → Cookies).
4. Scan the vulnerable pages one at a time (DVWA needs the login cookie):

```bash
python scanner.py -u http://localhost:8080/vulnerabilities/sqli/       --depth 0 --cookie "PHPSESSID=<your id>; security=low" --report dvwa_sqli
python scanner.py -u http://localhost:8080/vulnerabilities/sqli_blind/ --depth 0 --cookie "PHPSESSID=<your id>; security=low" --report dvwa_blind
python scanner.py -u http://localhost:8080/vulnerabilities/xss_r/      --depth 0 --cookie "PHPSESSID=<your id>; security=low" --report dvwa_xss
python scanner.py -u http://localhost:8080/vulnerabilities/csrf/       --depth 0 --cookie "PHPSESSID=<your id>; security=low" --report dvwa_csrf
```

**Expected findings on "Low" security:**

| Page | Expected finding |
|---|---|
| `/vulnerabilities/sqli/` | SQL Injection (error-based, MySQL) in `id` |
| `/vulnerabilities/sqli_blind/` | SQL Injection (time-based blind) in `id` (no error is shown, so only the timing check finds it) |
| `/vulnerabilities/xss_r/` | Reflected XSS in `name` |
| `/vulnerabilities/csrf/` | CSRF (sensitive action via GET), because the change-password form uses GET |
| any page | Cookie without SameSite: only if DVWA sends a `Set-Cookie` during the scan (cookies you pass with `--cookie` are not checked) |

Try **Medium/High/Impossible** too. Some findings should disappear as the protections get stronger (for example, the Impossible level adds a `user_token` CSRF token). This shows the scanner reacts to real defences.

> `setup.php` and `logout` are skipped by default so the scan doesn't reset DVWA's database or end your session.

> **My results:** *(paste your own summaries here)*

### 3. Local self-test (used during development)

During development, the scanner was run against a small local test server with one SQLi page (SQLite), one reflecting search page, one properly escaped page, a POST form with and without a CSRF token, and cookies with and without SameSite. It reported exactly the 5 expected issues. It did **not** flag the escaped page, the token-protected form or the `SameSite=Lax` cookie. The time-based check was also verified against a simulated `SLEEP(5)` endpoint.

---

## Limitations

- **False positives:** the time-based check can be fooled by a slow network or server (we send the payload twice to reduce this). The CSRF form check only looks at field *names*, so a token with an unusual name is missed, and a field that merely contains "token" counts as one. The SameSite check flags cookies even when they aren't used for authentication. **Always verify findings manually.**
- **False negatives:** only a few payloads are tried. WAFs, input filters, or injection points needing special syntax will be missed. Stored XSS, DOM-based XSS, and second-order SQLi are not detected.
- **No JavaScript support:** pages are fetched as raw HTML. Single-page apps (React/Angular/Vue) and links or forms created by JavaScript are invisible to the crawler.
- **Limited login support:** there is no automatic login. You can pass session cookies with `--cookie`, but if the session expires or a CSRF token changes per request, the scan may silently test the login page instead.
- **Only GET/POST forms and URL parameters:** JSON APIs, headers, cookies-as-input and file uploads are not tested.
- **Side effects:** the scanner submits forms, so on a real application it could create comments, send messages or change settings. Use it only on test systems.
- **Speed:** it is single-threaded with a delay, and the time-based check adds about 5 s per vulnerable payload. Use `--max-pages` and `--depth` to limit scan size.

## Disclaimer

This project was created **for educational purposes only** as a college project to learn how web vulnerabilities are found. Use it only on applications you own or have explicit written permission to test, such as DVWA running locally or public practice sites like testphp.vulnweb.com. Unauthorised scanning of websites is illegal and unethical. The author is not responsible for any misuse or damage caused by this tool.
