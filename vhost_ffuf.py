#!/usr/bin/env python3
import argparse
import ipaddress
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


def validate_ipv4(ip: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
        return ip
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid IPv4 address: {ip}"
        ) from exc


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Expected an integer, got: {value}"
        ) from exc

    if number < 1:
        raise argparse.ArgumentTypeError(
            "Value must be at least 1"
        )

    return number


def command_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def get_baseline_size(
    ip: str,
    hostname: str,
    scheme: str,
    fake_host: str,
    insecure: bool,
    prefix: str = "",
    suffix: str = "",
) -> int:
    url = f"{scheme}://{ip}/"
    host_header = f"{prefix}{fake_host}{suffix}.{hostname}"

    cmd = [
        "curl",
        "-sS",
        "--connect-timeout",
        "8",
        "--max-time",
        "15",
        "-H",
        f"Host: {host_header}",
        url,
    ]

    if scheme == "https" and insecure:
        cmd.insert(1, "-k")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=False,
    )

    if result.returncode != 0:
        print(
            "[!] curl failed while getting baseline size.",
            file=sys.stderr,
        )
        print(
            result.stderr.decode(errors="ignore").strip(),
            file=sys.stderr,
        )
        raise SystemExit(1)

    return len(result.stdout)


def build_ffuf_command(
    ip: str,
    hostname: str,
    scheme: str,
    wordlist: str,
    baseline_size: int,
    output: str | None,
    threads: int,
    insecure: bool,
    prefix: str = "",
    suffix: str = "",
    extra_filters: list[str] | None = None,
) -> list[str]:
    url = f"{scheme}://{ip}/"
    fuzz_host = f"{prefix}FUZZ{suffix}.{hostname}"

    cmd = [
        "ffuf",
        "-u",
        url,
        "-H",
        f"Host: {fuzz_host}",
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
        cmd.extend([
            "-o",
            output,
            "-of",
            "html",
        ])

    if extra_filters:
        cmd.extend(extra_filters)

    return cmd


def run_ffuf(command: list[str]) -> int:
    print("\n[+] Running ffuf command:\n")
    print(shlex.join(command))
    print()

    return subprocess.run(command).returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "VHOST brute-force helper: calculate a fake Host "
            "baseline size, then run ffuf."
        )
    )

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        type=validate_ipv4,
        help="Target IPv4 address, e.g. 10.129.22.188",
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Known hostname/domain, e.g. example.htb",
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
        help="Fake label used to calculate baseline response size.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Optional ffuf HTML output file.",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=positive_int,
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
        help="Show the baseline and ffuf command without running ffuf.",
    )

    parser.add_argument(
        "--prefix",
        default="",
        help=(
            "Literal text placed before FUZZ. "
            "Example: v1_ creates v1_FUZZ.domain"
        ),
    )

    parser.add_argument(
        "--suffix",
        default="",
        help=(
            "Literal text placed after FUZZ. "
            "Example: 001 creates FUZZ001.domain"
        ),
    )

    args = parser.parse_args()

    if not command_exists("curl"):
        print(
            "[!] curl is not installed or not in PATH.",
            file=sys.stderr,
        )
        return 1

    # A dry run does not need ffuf installed because it only prints
    # the command.
    if not args.dry_run and not command_exists("ffuf"):
        print(
            "[!] ffuf is not installed or not in PATH.",
            file=sys.stderr,
        )
        print(
            "Install with: sudo apt install ffuf",
            file=sys.stderr,
        )
        return 1

    if not Path(args.wordlist).is_file():
        print(
            f"[!] Wordlist not found: {args.wordlist}",
            file=sys.stderr,
        )
        return 1

    print(f"[+] Target IP:       {args.ip}")
    print(f"[+] Known hostname:  {args.domain}")
    print(f"[+] Scheme:          {args.scheme}")
    print(f"[+] Wordlist:        {args.wordlist}")
    print(f"[+] Prefix:          {args.prefix or '(none)'}")
    print(f"[+] Suffix:          {args.suffix or '(none)'}")

    baseline_size = get_baseline_size(
        ip=args.ip,
        hostname=args.domain,
        scheme=args.scheme,
        fake_host=args.fake_host,
        insecure=args.insecure,
        prefix=args.prefix,
        suffix=args.suffix,
    )

    fake_fqdn = (
        f"{args.prefix}"
        f"{args.fake_host}"
        f"{args.suffix}."
        f"{args.domain}"
    )

    fuzz_fqdn = (
        f"{args.prefix}"
        f"FUZZ"
        f"{args.suffix}."
        f"{args.domain}"
    )

    print(f"[+] Fake Host tested: {fake_fqdn}")
    print(f"[+] Fuzz Host format: {fuzz_fqdn}")
    print(f"[+] Baseline size:   {baseline_size}")
    print(f"[+] ffuf filter:     -fs {baseline_size}")

    ffuf_command = build_ffuf_command(
        ip=args.ip,
        hostname=args.domain,
        scheme=args.scheme,
        wordlist=args.wordlist,
        baseline_size=baseline_size,
        output=args.output,
        threads=args.threads,
        insecure=args.insecure,
        prefix=args.prefix,
        suffix=args.suffix,
        extra_filters=[],
    )

    if args.dry_run:
        print("\n[+] Dry-run ffuf command:\n")
        print(shlex.join(ffuf_command))
        return 0

    return run_ffuf(ffuf_command)


if __name__ == "__main__":
    raise SystemExit(main())
