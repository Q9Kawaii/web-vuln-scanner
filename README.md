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

## How to Use (Step by Step)

This guide assumes you have never run a Python tool before. Commands are given for **Windows** (Command Prompt or PowerShell) and **Mac/Linux** (Terminal).

### 1. Requirements

| You need | Check if installed | Get it |
|---|---|---|
| **Python 3.8 or newer** | `python --version` (Mac/Linux: `python3 --version`) | https://www.python.org/downloads/ (on Windows, tick **"Add Python to PATH"** during install) |
| **pip** (Python package installer, comes with Python) | `pip --version` (Mac/Linux: `pip3 --version`) | Included with Python |
| **git** | `git --version` | https://git-scm.com/downloads |

> On Mac/Linux, the commands are often `python3` and `pip3` instead of `python` and `pip`. Use whichever works on your machine.

### 2. Download the project (clone)

```bash
git clone https://github.com/Q9Kawaii/web-vuln-scanner.git
cd web-vuln-scanner
```

### 3. (Optional) Create a virtual environment

A virtual environment keeps this project's libraries separate from the rest of your system. It's recommended but not required.

**Windows:**
```bat
python -m venv venv
venv\Scripts\activate
```

**Mac / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

When it is active, you will see `(venv)` at the start of your command line. Type `deactivate` to leave it.

### 4. Install the required libraries

```bash
pip install -r requirements.txt
```

This installs `requests`, `beautifulsoup4`, `Jinja2` and `colorama`.

### 5. Run a scan

```bash
python scanner.py -u <target-url> --depth 1 --checks sqli,xss,csrf --report report
```

For example, to scan the public practice site:

```bash
python scanner.py -u http://testphp.vulnweb.com/ --depth 1 --checks sqli,xss,csrf --report report
```

The scanner first shows a warning and asks for permission. Type `yes` and press Enter to start. Typing anything else cancels the scan.

### 6. What the options mean

| Option | What it does | Example |
|---|---|---|
| `-u` | The website address to start scanning from (required) | `-u http://testphp.vulnweb.com/` |
| `--depth` | How many links deep to follow. `0` = only the start page, `1` = start page + pages it links to | `--depth 1` |
| `--checks` | Which tests to run, separated by commas: `sqli`, `xss`, `csrf` | `--checks xss,csrf` |
| `--report` | Name for the report files (without extension) | `--report report` → `report.html` and `report.json` |

Run `python scanner.py --help` to see all options (delay, timeout, cookies, and so on).

### 7. Sample output

Shortened output from a scan of a small local test site (`...` marks lines that were cut):

```
==================================================
  VulnScan - SQLi / XSS / CSRF detector
  Black-box, detection only - educational use
==================================================

WARNING: Only scan websites you own or have written permission to test.
Scanning other sites without permission may be illegal.
Do you have permission to scan this target? Type 'yes' to continue: yes

[1] Crawling http://127.0.0.1:8765/ (depth 1)
  [crawl] depth=0 forms=2 http://127.0.0.1:8765/
  [crawl] depth=1 forms=0 http://127.0.0.1:8765/user?id=1
  [crawl] depth=1 forms=1 http://127.0.0.1:8765/search
  [crawl] depth=1 forms=0 http://127.0.0.1:8765/safe?q=x
Found 4 page(s) and 5 testable target(s).

[2] Running checks: sqli, xss, csrf
  [sqli] GET http://127.0.0.1:8765/user -> id
    [!] SQL Injection (error-based) in 'id'
  ...
  [xss] GET http://127.0.0.1:8765/search -> q
    [!] Reflected XSS in 'q'
  ...
  [csrf] analysing 3 forms and 12 Set-Cookie headers
    [!] CSRF (no anti-CSRF token) at http://127.0.0.1:8765/comment
    [!] CSRF (cookie without SameSite) at http://127.0.0.1:8765/

=== Scan summary: 5 finding(s) ===
[High] SQL Injection (error-based)
    URL:       GET http://127.0.0.1:8765/user
    Parameter: id
    Payload:   1'
...

Reports saved: report.html, report.json
```

The report files are saved in the **folder you ran the command from** (normally the `web-vuln-scanner` folder):

- `report.html` is a readable report with a colour-coded table of findings
- `report.json` holds the same data in a machine-readable format

### 8. Open the HTML report

Double-click `report.html` in your file explorer, or open it from the command line:

| System | Command |
|---|---|
| Windows | `start report.html` |
| Mac | `open report.html` |
| Linux | `xdg-open report.html` |

### 9. Safe practice targets

Only practise on sites that are **made for testing**:

**testphp.vulnweb.com:** a public, intentionally vulnerable site run by Acunetix. Nothing to install:
```bash
python scanner.py -u http://testphp.vulnweb.com/ --depth 1 --report report
```

**DVWA (Damn Vulnerable Web Application):** runs on your own computer using Docker.
1. Install Docker Desktop: https://www.docker.com/products/docker-desktop/
2. Start DVWA:
   ```bash
   docker run --rm -it -p 8080:80 vulnerables/web-dvwa
   ```
3. Open http://localhost:8080 and log in with `admin` / `password`.
4. Click **Create / Reset Database**, log in again, then go to **DVWA Security** and set the level to **Low**.
5. Copy your `PHPSESSID` cookie (browser DevTools → Application/Storage → Cookies) and scan a page:
   ```bash
   python scanner.py -u http://localhost:8080/vulnerabilities/xss_r/ --depth 0 --cookie "PHPSESSID=<your id>; security=low" --report dvwa
   ```
6. Stop DVWA by pressing `Ctrl+C` in the Docker window.

See the [Testing](#testing) section below for which results to expect.

### 10. ⚠️ Warning

**Only scan websites you own or have clear permission to test.** Scanning someone else's website without permission can be illegal, even if you don't cause any damage. The scanner submits forms and sends many requests, so never point it at real, live websites.

### 11. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` / `python: command not found` | **Windows:** reinstall Python and tick **"Add Python to PATH"**, or try `py scanner.py ...`. **Mac/Linux:** use `python3` instead of `python`. |
| `ModuleNotFoundError: No module named 'requests'` (or `bs4`, `jinja2`, `colorama`) | Run `pip install -r requirements.txt` again from inside the project folder. If you made a virtual environment, activate it first. On Mac/Linux try `pip3` or `python3 -m pip install -r requirements.txt`. |
| `Could not load any HTML page from the target` / connection timeout | Check the URL in a browser first and include `http://` or `https://`. The site may be down or blocked by your network (college Wi-Fi often blocks such sites, so try mobile data). For slow sites, increase the timeout: `--timeout 30`. For DVWA, make sure the Docker container is still running. |
| The scan seems stuck on `[sqli]` | This is normal. The time-based SQL injection test waits about 5 seconds per payload. Use `--depth 0` or `--max-pages 10` for a quicker scan. |

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
