#!/usr/bin/env python3
import argparse
from pathlib import Path


INTERACTIVE_SHELLS = {
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/bin/ksh",
    "/bin/dash",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/zsh",
    "/usr/bin/dash",
}


def parse_passwd_file(passwd_file: Path, include_system: bool, all_shells: bool):
    users = []

    with passwd_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) != 7:
                print(f"[!] Skipping malformed line {line_number}: {line}")
                continue

            username, _, uid, gid, gecos, home, shell = parts

            try:
                uid_int = int(uid)
            except ValueError:
                print(f"[!] Skipping line {line_number}; invalid UID: {uid}")
                continue

            if not include_system and uid_int < 1000 and username != "root":
                continue

            if not all_shells and shell not in INTERACTIVE_SHELLS:
                continue

            users.append({
                "username": username,
                "uid": uid_int,
                "gid": gid,
                "gecos": gecos,
                "home": home,
                "shell": shell,
            })

    return users


def main():
    parser = argparse.ArgumentParser(
        description="Extract Linux usernames from a supplied /etc/passwd file."
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to the passwd file you want to parse, e.g. passwd.txt",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="users.txt",
        help="Output file for usernames. Default: users.txt",
    )

    parser.add_argument(
        "--include-system",
        action="store_true",
        help="Include system users with UID below 1000.",
    )

    parser.add_argument(
        "--all-shells",
        action="store_true",
        help="Include users with nologin/false shells.",
    )

    args = parser.parse_args()

    passwd_file = Path(args.file)
    output_file = Path(args.output)

    if not passwd_file.exists():
        raise SystemExit(f"[!] Passwd file not found: {passwd_file}")

    users = parse_passwd_file(
        passwd_file=passwd_file,
        include_system=args.include_system,
        all_shells=args.all_shells,
    )

    if not users:
        raise SystemExit("[!] No users found with the selected filters.")

    unique_users = sorted({user["username"] for user in users})

    print("\n[+] Parsed users:\n")

    for user in users:
        print(
            f"{user['username']:<20} "
            f"UID={user['uid']:<6} "
            f"HOME={user['home']:<30} "
            f"SHELL={user['shell']}"
        )

    output_file.write_text("\n".join(unique_users) + "\n", encoding="utf-8")

    print(f"\n[+] Wrote {len(unique_users)} usernames to: {output_file}")

    print("\n[+] nxc example:")
    print(f"    nxc ssh <TARGET_IP> -u {output_file} -p '<PASSWORD>'")


if __name__ == "__main__":
    main()
