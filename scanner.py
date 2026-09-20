import argparse
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HSTS",
        "Enforces HTTPS connections in supporting browsers."
    ),
    "Content-Security-Policy": (
        "CSP",
        "Helps control which resources a browser is allowed to load."
    ),
    "X-Frame-Options": (
        "Clickjacking Protection",
        "Helps prevent the page from being embedded in frames."
    ),
    "X-Content-Type-Options": (
        "MIME Sniffing Protection",
        "Helps prevent browsers from MIME-sniffing responses."
    ),
    "Referrer-Policy": (
        "Referrer Policy",
        "Controls how much referrer information browsers send."
    ),
}


VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def print_banner():
    RED = "\033[91m"
    DARK_RED = "\033[31m"
    WHITE = "\033[97m"
    RESET = "\033[0m"

    print(f"""
{RED} _       __     __   ____   ____  _____    ____  ____
| |     / /__  / /  / __ \ / __ \/ ___/   / __ \/ __ \
| | /| / / _ \/ /  / /_/ // /_/ / /       / /_/ / /_/ /
| |/ |/ /  __/ /  / _, _// ____/ /___    / _, _/ ____
|__/|__/\___/_/  /_/ |_/_/    \____/   /_/ |_/_/
{RESET}
{DARK_RED}==================== W E B R E A P E R ===================={RESET}
{WHITE}                 WEB SECURITY ANALYZER{RESET}
""")

def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.netloc:
        return False

    return True


def scan_target(url):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(X11; Linux x86_64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        )
    }

    try:
        return requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True
        )

    except requests.exceptions.SSLError:
        print("[!] Error: SSL/TLS certificate verification failed.")
        sys.exit(1)

    except requests.exceptions.ConnectionError:
        print("[!] Error: Unable to connect to target.")
        sys.exit(1)

    except requests.exceptions.Timeout:
        print("[!] Error: Request timed out.")
        sys.exit(1)

    except requests.exceptions.RequestException as error:
        print(f"[!] Error: {error}")
        sys.exit(1)


def add_finding(findings, severity, title, description, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
    })


def check_security_headers(response):
    present = []
    missing = []

    for header, (name, description) in SECURITY_HEADERS.items():

        if header in response.headers:
            present.append(name)
        else:
            missing.append({
                "header": name,
                "description": description
            })

    return present, missing


def analyze_hsts(response, findings):
    hsts = response.headers.get("Strict-Transport-Security")

    if not hsts:
        add_finding(
            findings,
            "MEDIUM",
            "Missing HSTS",
            "Strict-Transport-Security is not present.",
            "Consider enabling HSTS after validating HTTPS across the domain."
        )
        return {
            "present": False
        }

    directives = {}

    for part in hsts.split(";"):
        part = part.strip()

        if not part:
            continue

        if "=" in part:
            key, value = part.split("=", 1)
            directives[key.strip().lower()] = value.strip()
        else:
            directives[part.lower()] = True

    result = {
        "present": True,
        "max_age": None,
        "include_subdomains": False,
        "preload": False,
    }

    max_age = directives.get("max-age")

    if max_age is None:
        add_finding(
            findings,
            "MEDIUM",
            "HSTS max-age missing",
            "HSTS is present but does not define max-age.",
            "Configure a valid max-age value."
        )

    elif str(max_age).isdigit():
        result["max_age"] = int(max_age)

        if int(max_age) < 31536000:
            add_finding(
                findings,
                "LOW",
                "Short HSTS max-age",
                "The HSTS max-age is less than one year.",
                "Consider using an HSTS max-age of at least one year after testing."
            )

    else:
        add_finding(
            findings,
            "MEDIUM",
            "Invalid HSTS max-age",
            "The HSTS max-age value is not numeric.",
            "Configure max-age using a valid number of seconds."
        )

    if "includesubdomains" in directives:
        result["include_subdomains"] = True
    else:
        add_finding(
            findings,
            "LOW",
            "HSTS does not include subdomains",
            "includeSubDomains is not present in the HSTS policy.",
            "Consider including subdomains if HTTPS is enforced across them."
        )

    if "preload" in directives:
        result["preload"] = True

    return result


def analyze_csp(response, findings):
    csp = response.headers.get("Content-Security-Policy")

    if not csp:
        add_finding(
            findings,
            "MEDIUM",
            "Missing Content-Security-Policy",
            "Content-Security-Policy is not present.",
            "Consider implementing a CSP appropriate for the application's resources."
        )
        return {
            "present": False,
            "directives": []
        }

    directives = []

    for part in csp.split(";"):
        part = part.strip()

        if not part:
            continue

        directive = part.split()[0].lower()
        directives.append(directive)

    if "default-src" not in directives:
        add_finding(
            findings,
            "LOW",
            "CSP missing default-src",
            "The CSP does not define a default-src directive.",
            "Consider defining default-src where appropriate."
        )

    if "script-src" not in directives:
        add_finding(
            findings,
            "LOW",
            "CSP missing script-src",
            "The CSP does not explicitly define script-src.",
            "Consider defining script-src where appropriate."
        )

    return {
        "present": True,
        "directives": directives
    }


def analyze_x_frame_options(response, findings):
    value = response.headers.get("X-Frame-Options")

    if not value:
        add_finding(
            findings,
            "MEDIUM",
            "Missing X-Frame-Options",
            "X-Frame-Options is not present.",
            "Consider using DENY or SAMEORIGIN where appropriate."
        )

        return {
            "present": False,
            "value": None,
            "valid": False
        }

    value = value.strip().upper()

    result = {
        "present": True,
        "value": value,
        "valid": value in ("DENY", "SAMEORIGIN")
    }

    if value not in ("DENY", "SAMEORIGIN"):
        add_finding(
            findings,
            "LOW",
            "Unrecognized X-Frame-Options configuration",
            f"The returned value is '{value}'.",
            "Review the X-Frame-Options configuration."
        )

    return result


def analyze_content_type_options(response, findings):
    value = response.headers.get("X-Content-Type-Options")

    if not value:
        add_finding(
            findings,
            "LOW",
            "Missing X-Content-Type-Options",
            "X-Content-Type-Options is not present.",
            "Consider setting X-Content-Type-Options to nosniff."
        )

        return {
            "present": False,
            "value": None,
            "valid": False
        }

    value = value.strip().lower()

    result = {
        "present": True,
        "value": value,
        "valid": value == "nosniff"
    }

    if value != "nosniff":
        add_finding(
            findings,
            "LOW",
            "Invalid X-Content-Type-Options",
            f"The returned value is '{value}'.",
            "Set X-Content-Type-Options to nosniff."
        )

    return result


def analyze_referrer_policy(response, findings):
    value = response.headers.get("Referrer-Policy")

    if not value:
        add_finding(
            findings,
            "LOW",
            "Missing Referrer-Policy",
            "Referrer-Policy is not present.",
            "Consider defining an appropriate Referrer-Policy."
        )

        return {
            "present": False,
            "value": None,
            "recognized": False
        }

    policies = [
        policy.strip().lower()
        for policy in value.split(",")
        if policy.strip()
    ]

    recognized = [
        policy
        for policy in policies
        if policy in VALID_REFERRER_POLICIES
    ]

    if not recognized:
        add_finding(
            findings,
            "LOW",
            "Unrecognized Referrer-Policy",
            f"The returned value is '{value}'.",
            "Review the Referrer-Policy configuration."
        )

    return {
        "present": True,
        "value": value,
        "recognized": bool(recognized),
        "recognized_policies": recognized
    }


def print_header_status(response):
    print("\nSecurity Headers:")
    print("-" * 40)

    for header, (name, _) in SECURITY_HEADERS.items():

        if header in response.headers:
            print(f"[+] {name}: PRESENT")
        else:
            print(f"[-] {name}: MISSING")


def print_analysis(results):
    hsts = results["hsts"]
    csp = results["csp"]
    x_frame = results["x_frame_options"]
    content_type = results["content_type_options"]
    referrer = results["referrer_policy"]

    print("\nHSTS Analysis:")
    print("-" * 40)

    if not hsts["present"]:
        print("[-] HSTS: MISSING")
    else:
        print("[+] HSTS: PRESENT")

        if hsts["max_age"] is not None:
            print(f"[+] max-age: {hsts['max_age']}")

            if hsts["max_age"] >= 31536000:
                print("[+] max-age duration: 1 year or more")
            else:
                print("[-] max-age duration: Less than 1 year")

        else:
            print("[-] max-age: MISSING")

        if hsts["include_subdomains"]:
            print("[+] includeSubDomains: YES")
        else:
            print("[-] includeSubDomains: NO")

        if hsts["preload"]:
            print("[+] preload: YES")
        else:
            print("[*] preload: NO")

    print("\nCSP Analysis:")
    print("-" * 40)

    if not csp["present"]:
        print("[-] CSP: MISSING")
    else:
        print("[+] CSP: PRESENT")
        print(f"[+] Directives detected: {len(csp['directives'])}")

        if "default-src" in csp["directives"]:
            print("[+] default-src: PRESENT")
        else:
            print("[*] default-src: NOT FOUND")

        if "script-src" in csp["directives"]:
            print("[+] script-src: PRESENT")
        else:
            print("[*] script-src: NOT FOUND")

    print("\nX-Frame-Options Analysis:")
    print("-" * 40)

    if not x_frame["present"]:
        print("[-] X-Frame-Options: MISSING")
    else:
        print(f"[+] Value: {x_frame['value']}")

        if x_frame["valid"]:
            print("[+] Configuration: VALID")
        else:
            print("[-] Configuration: UNRECOGNIZED")

    print("\nX-Content-Type-Options Analysis:")
    print("-" * 40)

    if not content_type["present"]:
        print("[-] Header: MISSING")
    else:
        print(f"[+] Value: {content_type['value']}")

        if content_type["valid"]:
            print("[+] Configuration: VALID")
        else:
            print("[-] Configuration: INVALID")

    print("\nReferrer-Policy Analysis:")
    print("-" * 40)

    if not referrer["present"]:
        print("[-] Referrer-Policy: MISSING")
    else:
        print(f"[+] Value: {referrer['value']}")

        if referrer["recognized"]:
            print("[+] Configuration: RECOGNIZED")

            if len(referrer["recognized_policies"]) > 1:
                print(
                    f"[+] Recognized policies: "
                    f"{len(referrer['recognized_policies'])}"
                )
        else:
            print("[-] Configuration: UNRECOGNIZED")


def print_findings(findings):
    print("\nFindings:")
    print("-" * 40)

    if not findings:
        print("[+] No issues detected in the checked configurations.")
        return

    severity_order = {
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    findings = sorted(
        findings,
        key=lambda item: severity_order.get(item["severity"], 99)
    )

    for finding in findings:
        print(f"[{finding['severity']}] {finding['title']}")
        print(f"    {finding['description']}")
        print(f"    Recommendation: {finding['recommendation']}")
        print()


def create_report(
    target,
    response,
    results,
    findings,
    duration,
    coverage
):
    return {
        "scan": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "final_url": response.url,
            "status_code": response.status_code,
            "https": urlparse(response.url).scheme == "https",
            "duration_seconds": round(duration, 3)
        },
        "coverage": {
            "present": coverage["present"],
            "total": coverage["total"],
            "percentage": round(
                (coverage["present"] / coverage["total"]) * 100,
                2
            )
        },
        "analysis": results,
        "findings": findings
    }


def save_json_report(report):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"

    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"\n[+] JSON report saved: {filename}")

    except OSError as error:
        print(f"\n[!] Unable to save JSON report: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Web Security Header Scanner"
    )

    parser.add_argument(
        "url",
        help="Target URL, for example https://example.com"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Save scan results as a JSON report"
    )

    args = parser.parse_args()

    print_banner()

    url = args.url.strip()

    if not validate_url(url):
        print("[!] Error: Invalid URL.")
        print("[!] Please use http:// or https://")
        sys.exit(1)

    start_time = time.perf_counter()

    response = scan_target(url)

    duration = time.perf_counter() - start_time

    print(f"Target: {url}")
    print(f"Final URL: {response.url}")
    print(f"Status Code: {response.status_code}")

    parsed = urlparse(response.url)

    if parsed.scheme == "https":
        print("[+] HTTPS: ENABLED")
    else:
        print("[-] HTTPS: NOT USED")

    present, missing = check_security_headers(response)

    print_header_status(response)

    findings = []

    results = {
        "hsts": analyze_hsts(response, findings),
        "csp": analyze_csp(response, findings),
        "x_frame_options": analyze_x_frame_options(
            response,
            findings
        ),
        "content_type_options": analyze_content_type_options(
            response,
            findings
        ),
        "referrer_policy": analyze_referrer_policy(
            response,
            findings
        )
    }

    print_analysis(results)

    total = len(SECURITY_HEADERS)
    present_count = len(present)
    percentage = (present_count / total) * 100

    coverage = {
        "present": present_count,
        "total": total
    }

    print("\n" + "=" * 40)
    print(
        f"Security Header Coverage: "
        f"{present_count}/{total} ({percentage:.0f}%)"
    )
    print(f"Scan Duration: {duration:.2f} seconds")
    print("=" * 40)

    print_findings(findings)

    report = create_report(
        url,
        response,
        results,
        findings,
        duration,
        coverage
    )

    if args.json:
        save_json_report(report)


if __name__ == "__main__":
    main()
