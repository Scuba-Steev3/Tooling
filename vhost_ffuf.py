#!/usr/bin/env python3
import argparse
import ipaddress
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


def validate_ipv4(ip: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {ip}")


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def get_baseline_size(ip: str, hostname: str, scheme: str, fake_host: str, insecure: bool) -> int:
    url = f"{scheme}://{ip}/"
    host_header = f"{fake_host}.{hostname}"

    cmd = [
        "curl",
        "-s",
        "-H",
        f"Host: {host_header}",
        url,
    ]

    if scheme == "https" and insecure:
        cmd.insert(1, "-k")

    result = subprocess.run(cmd, capture_output=True, text=False)

    if result.returncode != 0:
        print("[!] curl failed while getting baseline size.", file=sys.stderr)
        print(result.stderr.decode(errors="ignore"), file=sys.stderr)
        sys.exit(1)

    return len(result.stdout)


def run_ffuf(
    ip: str,
    hostname: str,
    scheme: str,
    wordlist: str,
    baseline_size: int,
    output: str | None,
    threads: int,
    insecure: bool,
    extra_filters: list[str],
):
    url = f"{scheme}://{ip}/"

    cmd = [
        "ffuf",
        "-u",
        url,
        "-H",
        f"Host: FUZZ.{hostname}",
        "-w",
        wordlist,
        "-fs",
        str(baseline_size),
        "-t",
        str(threads),
    ]

    if scheme == "https" and insecure:
        cmd.append("-k")

    if output:
        cmd.extend(["-o", output, "-of", "html"])

    if extra_filters:
        cmd.extend(extra_filters)

    print("\n[+] Running ffuf command:\n")
    print(" ".join(cmd))
    print()

    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        description="VHOST brute-force helper: calculate fake Host baseline size, then run ffuf."
    )

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        type=validate_ipv4,
        help="Target IPv4 address, e.g. 10.129.227.180",
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Known hostname/domain, e.g. localdomain, example.htb, debian.localdomain",
    )

    parser.add_argument(
        "-s",
        "--scheme",
        choices=["http", "https"],
        default="http",
        help="Protocol to use. Default: http",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help=f"Wordlist path. Default: {DEFAULT_WORDLIST}",
    )

    parser.add_argument(
        "--fake-host",
        default="totallyfakevhost12345",
        help="Fake subdomain used to calculate baseline response size.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional ffuf HTML output file, e.g. ffuf_vhosts.html",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=40,
        help="ffuf thread count. Default: 40",
    )

    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Ignore HTTPS certificate errors.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only show baseline and ffuf command; do not run ffuf.",
    )

    args = parser.parse_args()

    if not command_exists("curl"):
        print("[!] curl is not installed or not in PATH.", file=sys.stderr)
        sys.exit(1)

    if not command_exists("ffuf"):
        print("[!] ffuf is not installed or not in PATH.", file=sys.stderr)
        print("Install with: sudo apt install ffuf", file=sys.stderr)
        sys.exit(1)

    if not Path(args.wordlist).exists():
        print(f"[!] Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Target IP:       {args.ip}")
    print(f"[+] Known hostname:  {args.domain}")
    print(f"[+] Scheme:          {args.scheme}")
    print(f"[+] Wordlist:        {args.wordlist}")

    baseline_size = get_baseline_size(
        ip=args.ip,
        hostname=args.domain,
        scheme=args.scheme,
        fake_host=args.fake_host,
        insecure=args.insecure,
    )

    fake_fqdn = f"{args.fake_host}.{args.domain}"

    print(f"[+] Fake Host tested: {fake_fqdn}")
    print(f"[+] Baseline size:   {baseline_size}")
    print(f"[+] ffuf filter:     -fs {baseline_size}")

    ffuf_cmd_preview = [
        "ffuf",
        "-u",
        f"{args.scheme}://{args.ip}/",
        "-H",
        f"Host: FUZZ.{args.domain}",
        "-w",
        args.wordlist,
        "-fs",
        str(baseline_size),
        "-t",
        str(args.threads),
    ]

    if args.scheme == "https" and args.insecure:
        ffuf_cmd_preview.append("-k")

    if args.output:
        ffuf_cmd_preview.extend(["-o", args.output, "-of", "html"])

    if args.dry_run:
        print("\n[+] Dry-run ffuf command:\n")
        print(" ".join(ffuf_cmd_preview))
        return

    run_ffuf(
        ip=args.ip,
        hostname=args.domain,
        scheme=args.scheme,
        wordlist=args.wordlist,
        baseline_size=baseline_size,
        output=args.output,
        threads=args.threads,
        insecure=args.insecure,
        extra_filters=[],
    )


if __name__ == "__main__":
    main()
