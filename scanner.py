"""
scanner.py - Command-line entry point for VulnScan.

Flow:  consent warning -> crawl the site -> run the selected checks -> save reports

Example:
    python scanner.py -u http://testphp.vulnweb.com/ --depth 2 --checks sqli,xss,csrf --report report
"""

import argparse
import sys

from colorama import Fore, Style, init

import report
from checks import csrf, sqli, xss
from crawler import DEFAULT_EXCLUDES, Crawler, HttpClient

ALL_CHECKS = ["sqli", "xss", "csrf"]

BANNER = f"""{Fore.GREEN}{Style.BRIGHT}
==================================================
  VulnScan - SQLi / XSS / CSRF detector
  Black-box, detection only - educational use
=================================================={Style.RESET_ALL}
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple black-box web vulnerability scanner (SQLi, XSS, CSRF). Detection only.")
    parser.add_argument("-u", "--url", required=True, help="Start URL, e.g. http://testphp.vulnweb.com/")
    parser.add_argument("--depth", type=int, default=2, help="How many links deep to crawl (default 2)")
    parser.add_argument("--checks", default="sqli,xss,csrf",
                        help="Comma-separated checks to run: sqli,xss,csrf (default all)")
    parser.add_argument("--report", default="scan_report",
                        help="Report file name without extension (default scan_report -> .html and .json)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default 50)")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds to wait between requests (default 0.5)")
    parser.add_argument("--timeout", type=float, default=10, help="Request timeout in seconds (default 10)")
    parser.add_argument("--cookie", help='Cookies for logged-in scanning, e.g. "PHPSESSID=abc; security=low"')
    parser.add_argument("--exclude", default=",".join(DEFAULT_EXCLUDES),
                        help="Comma-separated words; URLs containing them are skipped")
    return parser.parse_args()


def ask_consent():
    """Legal/ethical warning. The scan only starts if the user types 'yes'."""
    print(f"{Fore.YELLOW}{Style.BRIGHT}WARNING:{Style.RESET_ALL}{Fore.YELLOW} Only scan websites you own or "
          f"have written permission to test.\nScanning other sites without permission may be illegal."
          f"{Style.RESET_ALL}")
    answer = input("Do you have permission to scan this target? Type 'yes' to continue: ")
    return answer.strip().lower() == "yes"


def main():
    init()  # colorama: makes colours work on Windows terminals
    args = parse_args()
    print(BANNER)

    checks = [c.strip().lower() for c in args.checks.split(",") if c.strip()]
    unknown = [c for c in checks if c not in ALL_CHECKS]
    if unknown:
        sys.exit(f"Unknown check(s): {', '.join(unknown)}. Choose from: {', '.join(ALL_CHECKS)}")

    url = args.url if args.url.startswith(("http://", "https://")) else "http://" + args.url

    if not ask_consent():
        print("Scan cancelled.")
        return

    client = HttpClient(timeout=args.timeout, delay=args.delay, cookies=args.cookie)
    excludes = [e.strip() for e in args.exclude.split(",") if e.strip()]
    crawler = Crawler(client, url, max_depth=args.depth, max_pages=args.max_pages, excludes=excludes)

    findings = []
    pages = []
    try:
        print(f"\n{Style.BRIGHT}[1] Crawling {url} (depth {args.depth}){Style.RESET_ALL}")
        pages = crawler.crawl()
        if not pages:
            sys.exit("Could not load any HTML page from the target. Check the URL.")
        targets = crawler.build_targets(pages)
        print(f"Found {len(pages)} page(s) and {len(targets)} testable target(s).")

        print(f"\n{Style.BRIGHT}[2] Running checks: {', '.join(checks)}{Style.RESET_ALL}")
        if "sqli" in checks:
            findings += sqli.run(client, targets)
        if "xss" in checks:
            findings += xss.run(client, targets)
        if "csrf" in checks:
            findings += csrf.run(client, pages)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted - saving partial results.{Style.RESET_ALL}")

    report.print_summary(findings)
    info = {"target": url, "pages": len(pages), "requests": client.request_count, "checks": ", ".join(checks)}
    json_path, html_path = report.save_reports(findings, args.report, info)
    print(f"\nReports saved: {html_path}, {json_path}")


if __name__ == "__main__":
    main()
