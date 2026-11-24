from __future__ import annotations

import sys
import warnings
from dataclasses import dataclass, field
from typing import ClassVar

import requests

# Hide macOS LibreSSL warning in urllib3
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


@dataclass
class AuditReport:
    target_url: str
    final_url: str
    status_code: int
    passed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    leaks: list[str] = field(default_factory=list)
    score: int = 100

    @property
    def grade(self) -> str:
        if self.score >= 90:
            return "A"
        if self.score >= 75:
            return "B"
        if self.score >= 60:
            return "C"
        if self.score >= 40:
            return "D"
        return "F"

    @property
    def grade_color(self) -> str:
        if self.grade == "A":
            return Colors.GREEN
        if self.grade in ("B", "C"):
            return Colors.YELLOW
        return Colors.RED


class HeaderScanner:
    SECURITY_HEADERS: ClassVar[dict[str, tuple[str, int]]] = {
        "strict-transport-security": ("HSTS (prevents HTTP downgrade attacks)", 20),
        "content-security-policy": ("CSP (mitigates XSS and script injection)", 25),
        "x-frame-options": ("X-Frame-Options (prevents Clickjacking)", 15),
        "x-content-type-options": ("X-Content-Type-Options (prevents MIME-sniffing)", 15),
        "referrer-policy": ("Referrer-Policy (controls Referer header leakage)", 10),
        "permissions-policy": ("Permissions-Policy (restricts browser features/APIs)", 15),
    }

    LEAK_HEADERS = ("server", "x-powered-by", "x-aspnet-version")

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityHeaderAuditor/1.0)"
        })

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def scan(self, target_url: str) -> AuditReport | None:
        normalized_url = self._normalize_url(target_url)

        try:
            response = self.session.get(
                normalized_url,
                timeout=self.timeout,
                allow_redirects=True
            )
        except requests.RequestException as err:
            print(f"{Colors.RED}[!] Connection error for {normalized_url}: {err}{Colors.RESET}")
            return None

        headers = {k.lower(): v for k, v in response.headers.items()}

        report = AuditReport(
            target_url=normalized_url,
            final_url=response.url,
            status_code=response.status_code,
        )

        self._check_security_headers(headers, report)
        self._check_leaks(headers, report)
        report.score = max(0, report.score)
        return report

    def _check_security_headers(self, headers: dict[str, str], report: AuditReport) -> None:
        for header_key, (description, penalty) in self.SECURITY_HEADERS.items():
            value = headers.get(header_key)

            if header_key == "x-frame-options" and not value:
                csp = headers.get("content-security-policy", "")
                if "frame-ancestors" in csp.lower():
                    report.passed.append("Clickjacking protection (via CSP frame-ancestors)")
                    continue

            if not value:
                report.warnings.append(f"Missing {description}")
                report.score -= penalty
                continue

            if header_key == "x-content-type-options" and value.lower() != "nosniff":
                report.warnings.append(f"Invalid X-Content-Type-Options value: {value}")
                report.score -= penalty
            elif header_key == "strict-transport-security" and "max-age=0" in value.lower():
                report.warnings.append("HSTS is disabled (max-age=0)")
                report.score -= penalty
            else:
                report.passed.append(f"{description} -> {value[:60]}")

    def _check_leaks(self, headers: dict[str, str], report: AuditReport) -> None:
        for leak_key in self.LEAK_HEADERS:
            if leak_key in headers:
                report.leaks.append(f"{leak_key}: {headers[leak_key]}")
                report.score -= 5


def print_report(report: AuditReport) -> None:
    color = report.grade_color
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Target:{Colors.RESET}        {report.target_url}")
    if report.final_url != report.target_url:
        print(f"{Colors.BOLD}Redirected to:{Colors.RESET} {report.final_url}")
    print(f"{Colors.BOLD}HTTP Status:{Colors.RESET}   {report.status_code}")
    print(f"{Colors.BOLD}Grade:{Colors.RESET}         {color}{Colors.BOLD}{report.grade} ({report.score}/100){Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

    print(f"\n{Colors.GREEN}[+] Configured Security Headers:{Colors.RESET}")
    for item in report.passed or ["None detected"]:
        print(f"  {Colors.GREEN}✓{Colors.RESET} {item}")

    print(f"\n{Colors.RED}[-] Missing or Misconfigured Headers:{Colors.RESET}")
    for item in report.warnings or ["No critical issues found"]:
        print(f"  {Colors.RED}✗{Colors.RESET} {item}")

    print(f"\n{Colors.YELLOW}[!] Information Disclosure (Fingerprinting):{Colors.RESET}")
    for item in report.leaks or ["No verbose server headers detected"]:
        print(f"  {Colors.YELLOW}⚠{Colors.RESET} {item}")
    print()


if __name__ == "__main__":
    # Take domains from terminal arguments, or use default list
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["github.com", "example.com"]

    scanner = HeaderScanner()
    for domain in targets:
        result = scanner.scan(domain)
        if result:
            print_report(result)