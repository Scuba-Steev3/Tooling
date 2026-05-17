#!/usr/bin/env python3
import argparse
import hashlib
import sys


# Pure Python MD4 fallback because some Python/OpenSSL builds do not expose hashlib.new("md4")
# Source logic adapted from the public-domain MD4 reference algorithm.
class MD4:
    def __init__(self, message=b""):
        self.remainder = b""
        self.count = 0
        self.h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
        ]
        if message:
            self.update(message)

    def update(self, message):
        self.count += len(message)
        message = self.remainder + message
        block_count = len(message) // 64

        for i in range(block_count):
            self._handle(message[i * 64:(i + 1) * 64])

        self.remainder = message[block_count * 64:]

    def digest(self):
        message = self.remainder
        bit_len = self.count * 8

        message += b"\x80"
        message += b"\x00" * ((56 - len(message) % 64) % 64)
        message += bit_len.to_bytes(8, byteorder="little")

        h_backup = self.h[:]

        for i in range(0, len(message), 64):
            self._handle(message[i:i + 64])

        result = b"".join(x.to_bytes(4, byteorder="little") for x in self.h)
        self.h = h_backup
        return result

    def hexdigest(self):
        return self.digest().hex()

    def _handle(self, block):
        def f(x, y, z):
            return ((x & y) | (~x & z)) & 0xFFFFFFFF

        def g(x, y, z):
            return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF

        def h(x, y, z):
            return (x ^ y ^ z) & 0xFFFFFFFF

        def rotl(x, n):
            x &= 0xFFFFFFFF
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

        x = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]
        a, b, c, d = self.h

        # Round 1
        s = [3, 7, 11, 19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = rotl((a + f(b, c, d) + x[k]), s[i % 4])
            elif i % 4 == 1:
                d = rotl((d + f(a, b, c) + x[k]), s[i % 4])
            elif i % 4 == 2:
                c = rotl((c + f(d, a, b) + x[k]), s[i % 4])
            else:
                b = rotl((b + f(c, d, a) + x[k]), s[i % 4])

        # Round 2
        s = [3, 5, 9, 13]
        order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                a = rotl((a + g(b, c, d) + x[k] + 0x5A827999), s[i % 4])
            elif i % 4 == 1:
                d = rotl((d + g(a, b, c) + x[k] + 0x5A827999), s[i % 4])
            elif i % 4 == 2:
                c = rotl((c + g(d, a, b) + x[k] + 0x5A827999), s[i % 4])
            else:
                b = rotl((b + g(c, d, a) + x[k] + 0x5A827999), s[i % 4])

        # Round 3
        s = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                a = rotl((a + h(b, c, d) + x[k] + 0x6ED9EBA1), s[i % 4])
            elif i % 4 == 1:
                d = rotl((d + h(a, b, c) + x[k] + 0x6ED9EBA1), s[i % 4])
            elif i % 4 == 2:
                c = rotl((c + h(d, a, b) + x[k] + 0x6ED9EBA1), s[i % 4])
            else:
                b = rotl((b + h(c, d, a) + x[k] + 0x6ED9EBA1), s[i % 4])

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF


def nt_hash(password: str) -> str:
    data = password.encode("utf-16le")

    try:
        return hashlib.new("md4", data).hexdigest()
    except ValueError:
        return MD4(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Generate an NT hash from a username and password."
    )

    parser.add_argument("-u", "--user", required=True, help="Target username")
    parser.add_argument("-p", "--password", required=True, help="Cracked plaintext password")
    parser.add_argument(
        "--format",
        choices=["userhash", "hash", "impacket", "all"],
        default="userhash",
        help=(
        	"Output format: "
        	"userhash=user:hash, "
        	"hash=hash only, "
        	"impacket=user:::hash:::, "
        	"all=print all formats"
    	),
    )

    args = parser.parse_args()
    hash_value = nt_hash(args.password)

    if args.format == "hash":
        print(hash_value)
    elif args.format == "impacket":
        print(f"{args.user}:::{hash_value}:::")
    else:
        print(f"{args.user}:{hash_value}")
    
    if args.format == "hash":
    	print(hash_value)

    elif args.format == "impacket":
    	print(f"{args.user}:::{hash_value}:::")

    elif args.format == "all":
    	print(f"[hash]     {hash_value}")
    	print(f"[userhash] {args.user}:{hash_value}")
    	print(f"[impacket] {args.user}:::{hash_value}:::")

    else:
    	print(f"{args.user}:{hash_value}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
