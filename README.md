# HTTP Security Headers Scanner

A lightweight Python CLI utility for auditing HTTP security response headers, detecting server stack information disclosure, and grading overall client-side hardening from **A** to **F**.

## Features

- **Core Security Headers Audit:** Evaluates presence and directive values for:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (with automatic fallback check for CSP `frame-ancestors`)
  - `X-Content-Type-Options` (`nosniff` validation)
  - `Referrer-Policy`
  - `Permissions-Policy`
- **Fingerprinting Detection:** Flags verbose headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) that leak infrastructure details.
- **Smart Grading System:** Calculates a weighted security score (0–100) and assigns a letter grade (`A`–`F`) with ANSI color-coded terminal output.
- **Redirect Tracking:** Follows HTTP-to-HTTPS redirect chains to inspect final destination headers.

## Requirements

- Python 3.9+
- `requests`

## Installation & Usage

1. Install the dependency:
   ```bash
   pip3 install requests
   ```

2. Run the scanner against one or multiple target domains:
   ```bash
   python3 header_scanner.py github.com example.com
   ```

## Example Output

```text
============================================================
Target:        [https://github.com](https://github.com)
Redirected to: [https://github.com/](https://github.com/)
HTTP Status:   200
Grade:         B (80/100)
============================================================

[+] Configured Security Headers:
  ✓ HSTS (prevents HTTP downgrade attacks) -> max-age=31536000; includeSubdomains; preload
  ✓ CSP (mitigates XSS and script injection) -> default-src 'none'; base-uri 'self'; child-src github.github
  ✓ X-Frame-Options (prevents Clickjacking) -> deny
  ✓ X-Content-Type-Options (prevents MIME-sniffing) -> nosniff
  ✓ Referrer-Policy (controls Referer header leakage) -> origin-when-cross-origin, strict-origin-when-cross-origin

[-] Missing or Misconfigured Headers:
  ✗ Missing Permissions-Policy (restricts browser features/APIs)

[!] Information Disclosure (Fingerprinting):
  ⚠ server: github.com
```

## Disclaimer

This tool is intended for educational purposes and authorized security assessments only.