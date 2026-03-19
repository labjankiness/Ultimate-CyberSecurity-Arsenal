#!/usr/bin/env python3
"""
Password Cracker — Educational Tool
Demonstrates dictionary attacks, brute-force, and hash cracking
to illustrate why strong passwords matter.

WARNING: For educational and authorized testing purposes only.
Never use against systems you don't own or have permission to test.
"""

import hashlib
import itertools
import string
import time
import argparse
import sys
import os


# ─── Hash Detection & Cracking ────────────────────────────────────────────────

HASH_TYPES = {
    32: [("md5", hashlib.md5)],
    40: [("sha1", hashlib.sha1)],
    64: [("sha256", hashlib.sha256)],
    128: [("sha512", hashlib.sha512)],
}


def identify_hash(hash_str):
    """Identify likely hash type based on length and character set."""
    h = hash_str.strip().lower()
    if not all(c in string.hexdigits for c in h):
        return []
    return HASH_TYPES.get(len(h), [])


def hash_password(password, algo):
    """Hash a password with the given algorithm."""
    return algo(password.encode()).hexdigest()


# ─── Built-in Common Passwords ─────────────────────────────────────────────────

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "michael", "shadow", "123123", "654321", "superman",
    "qazwsx", "football", "password1", "password123", "admin",
    "welcome", "hello", "charlie", "donald", "login",
    "princess", "starwars", "solo", "qwerty123", "passw0rd",
    "123456789", "1234567890", "000000", "111111", "121212",
    "access", "flower", "hottie", "loveme", "zaq1zaq1",
    "654321", "666666", "696969", "888888", "999999",
    "1q2w3e", "1q2w3e4r", "1qaz2wsx", "aa12345678", "abc1234",
    "abcdef", "amanda", "andrea", "andrew", "anthony",
    "batman", "biteme", "buster", "cheese", "cookie",
    "daniel", "george", "ginger", "harley", "hunter",
    "jennifer", "jessica", "jordan", "joshua", "maggie",
    "matthew", "michelle", "nicole", "pepper", "robert",
    "samantha", "summer", "thomas", "tigger", "trustno1",
    "william", "yankees", "soccer", "hockey", "ranger",
    "test", "test123", "root", "toor", "admin123",
    "administrator", "guest", "changeme", "default", "server",
]

# Common substitutions for rule-based mutations
LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


def mutate_word(word):
    """Generate common mutations of a password."""
    mutations = [word]

    # Capitalization variants
    mutations.append(word.capitalize())
    mutations.append(word.upper())
    mutations.append(word.lower())

    # Append numbers
    for n in ["1", "12", "123", "1234", "!", "!!", "69", "007"]:
        mutations.append(word + n)
        mutations.append(word.capitalize() + n)

    # Prepend numbers
    for n in ["1", "123"]:
        mutations.append(n + word)

    # Leet speak
    leet = word.lower()
    for orig, repl in LEET_MAP.items():
        leet = leet.replace(orig, repl)
    if leet != word.lower():
        mutations.append(leet)

    # Reverse
    mutations.append(word[::-1])

    return mutations


# ─── Dictionary Attack ─────────────────────────────────────────────────────────

def dictionary_attack(target_hash, algo, wordlist_path=None, use_mutations=True):
    """
    Attempt to crack a hash using a wordlist.

    Args:
        target_hash: The hash to crack
        algo: Hash function (e.g., hashlib.md5)
        wordlist_path: Path to a wordlist file (optional, uses built-in if None)
        use_mutations: Apply rule-based mutations to each word

    Returns:
        (password, attempts, elapsed) or (None, attempts, elapsed)
    """
    target = target_hash.strip().lower()
    attempts = 0
    start = time.time()

    # Build word list
    words = []
    if wordlist_path and os.path.exists(wordlist_path):
        with open(wordlist_path, "r", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"  Loaded {len(words)} words from {wordlist_path}")
    else:
        words = COMMON_PASSWORDS
        print(f"  Using built-in wordlist ({len(words)} words)")

    for word in words:
        candidates = mutate_word(word) if use_mutations else [word]
        for candidate in candidates:
            attempts += 1
            if hash_password(candidate, algo) == target:
                elapsed = time.time() - start
                return candidate, attempts, elapsed

            # Progress indicator every 10000 attempts
            if attempts % 10000 == 0:
                print(f"\r  Tried {attempts:,} candidates...", end="", flush=True)

    elapsed = time.time() - start
    print(f"\r  Tried {attempts:,} candidates.   ")
    return None, attempts, elapsed


# ─── Brute Force Attack ────────────────────────────────────────────────────────

def brute_force(target_hash, algo, charset=None, min_len=1, max_len=6):
    """
    Attempt to crack a hash by trying all possible combinations.

    Args:
        target_hash: The hash to crack
        algo: Hash function
        charset: Characters to use (default: lowercase + digits)
        min_len: Minimum password length to try
        max_len: Maximum password length to try

    Returns:
        (password, attempts, elapsed) or (None, attempts, elapsed)
    """
    target = target_hash.strip().lower()
    if charset is None:
        charset = string.ascii_lowercase + string.digits
    attempts = 0
    start = time.time()

    print(f"  Charset: {charset[:20]}{'...' if len(charset) > 20 else ''} ({len(charset)} chars)")
    print(f"  Length range: {min_len}-{max_len}")

    total_combos = sum(len(charset) ** l for l in range(min_len, max_len + 1))
    print(f"  Total combinations: {total_combos:,}")

    for length in range(min_len, max_len + 1):
        print(f"  Trying length {length} ({len(charset) ** length:,} combos)...")
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if hash_password(candidate, algo) == target:
                elapsed = time.time() - start
                return candidate, attempts, elapsed

            if attempts % 50000 == 0:
                rate = attempts / (time.time() - start) if time.time() > start else 0
                print(
                    f"\r  [{attempts:,} / {total_combos:,}] "
                    f"{rate:,.0f} hash/sec",
                    end="",
                    flush=True,
                )

    elapsed = time.time() - start
    print(f"\r  Exhausted {attempts:,} combinations.   ")
    return None, attempts, elapsed


# ─── Hash a Password (for testing) ────────────────────────────────────────────

def hash_demo(password, algo_name="md5"):
    """Hash a password and display the result for all common algorithms."""
    print(f"\n  Password: {password}")
    print(f"  {'Algorithm':<10} {'Hash'}")
    print(f"  {'─' * 10} {'─' * 64}")
    for name, func in [
        ("md5", hashlib.md5),
        ("sha1", hashlib.sha1),
        ("sha256", hashlib.sha256),
        ("sha512", hashlib.sha512),
    ]:
        h = func(password.encode()).hexdigest()
        display = h if len(h) <= 64 else h[:61] + "..."
        print(f"  {name:<10} {display}")
    print()


# ─── CLI ───────────────────────────────────────────────────────────────────────

def print_banner():
    print(
        r"""
  ╔═══════════════════════════════════════════╗
  ║     PASSWORD CRACKER — Educational Tool   ║
  ║  For authorized testing & learning only   ║
  ╚═══════════════════════════════════════════╝
"""
    )


def interactive_mode():
    """Interactive menu-driven interface."""
    print_banner()

    while True:
        print("  1. Crack a hash (dictionary attack)")
        print("  2. Crack a hash (brute force)")
        print("  3. Hash a password (generate test hashes)")
        print("  4. Identify hash type")
        print("  5. Exit")
        print()

        choice = input("  Choose (1-5): ").strip()
        print()

        if choice == "1":
            target = input("  Enter hash to crack: ").strip()
            if not target:
                print("  No hash provided.\n")
                continue

            candidates = identify_hash(target)
            if not candidates:
                print("  Could not identify hash type.\n")
                continue

            algo_name, algo = candidates[0]
            print(f"  Detected: {algo_name.upper()}")

            wordlist = input("  Wordlist path (Enter for built-in): ").strip() or None
            mutate = input("  Apply mutations? (Y/n): ").strip().lower() != "n"

            print(f"\n  Starting dictionary attack ({algo_name})...")
            result, attempts, elapsed = dictionary_attack(
                target, algo, wordlist, mutate
            )

            if result:
                print(f"\n  CRACKED! Password: {result}")
                print(f"  Attempts: {attempts:,} | Time: {elapsed:.2f}s")
            else:
                print(f"\n  Not found in wordlist.")
                print(f"  Attempts: {attempts:,} | Time: {elapsed:.2f}s")
            print()

        elif choice == "2":
            target = input("  Enter hash to crack: ").strip()
            if not target:
                print("  No hash provided.\n")
                continue

            candidates = identify_hash(target)
            if not candidates:
                print("  Could not identify hash type.\n")
                continue

            algo_name, algo = candidates[0]
            print(f"  Detected: {algo_name.upper()}")

            max_len = input("  Max password length (default 4): ").strip()
            max_len = int(max_len) if max_len.isdigit() else 4

            cs_choice = input("  Charset — [1] a-z+0-9  [2] a-zA-Z+0-9  [3] all printable (1): ").strip()
            if cs_choice == "2":
                charset = string.ascii_letters + string.digits
            elif cs_choice == "3":
                charset = string.ascii_letters + string.digits + string.punctuation
            else:
                charset = string.ascii_lowercase + string.digits

            print(f"\n  Starting brute force ({algo_name}, max length {max_len})...")
            print(f"  WARNING: This can be very slow for lengths > 5\n")
            result, attempts, elapsed = brute_force(
                target, algo, charset, 1, max_len
            )

            if result:
                print(f"\n  CRACKED! Password: {result}")
                print(f"  Attempts: {attempts:,} | Time: {elapsed:.2f}s")
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"  Rate: {rate:,.0f} hashes/sec")
            else:
                print(f"\n  Not found within length {max_len}.")
                print(f"  Attempts: {attempts:,} | Time: {elapsed:.2f}s")
            print()

        elif choice == "3":
            password = input("  Enter password to hash: ").strip()
            if password:
                hash_demo(password)

        elif choice == "4":
            h = input("  Enter hash: ").strip()
            candidates = identify_hash(h)
            if candidates:
                types = ", ".join(name.upper() for name, _ in candidates)
                print(f"  Likely type: {types} (length: {len(h)})\n")
            else:
                print(f"  Unknown hash type (length: {len(h)})\n")

        elif choice == "5":
            print("  Goodbye!\n")
            break

        else:
            print("  Invalid choice.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Password Cracker — Educational hash cracking tool",
        epilog="For authorized testing and learning purposes only.",
    )
    parser.add_argument("hash", nargs="?", help="Hash to crack")
    parser.add_argument(
        "-m", "--mode",
        choices=["dict", "brute"],
        default="dict",
        help="Attack mode: dict (dictionary) or brute (brute force)",
    )
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument(
        "--max-len",
        type=int,
        default=4,
        help="Max password length for brute force (default: 4)",
    )
    parser.add_argument(
        "--no-mutate",
        action="store_true",
        help="Disable rule-based mutations in dictionary mode",
    )
    parser.add_argument(
        "--generate",
        metavar="PASSWORD",
        help="Generate hashes for a given password",
    )

    args = parser.parse_args()

    # If no arguments, run interactive mode
    if not args.hash and not args.generate:
        interactive_mode()
        return

    # Generate mode
    if args.generate:
        print_banner()
        hash_demo(args.generate)
        return

    # Crack mode
    print_banner()
    target = args.hash
    candidates = identify_hash(target)
    if not candidates:
        print(f"  Could not identify hash type for: {target}")
        sys.exit(1)

    algo_name, algo = candidates[0]
    print(f"  Target: {target}")
    print(f"  Type:   {algo_name.upper()}\n")

    if args.mode == "dict":
        print("  Mode: Dictionary Attack")
        result, attempts, elapsed = dictionary_attack(
            target, algo, args.wordlist, not args.no_mutate
        )
    else:
        print("  Mode: Brute Force")
        result, attempts, elapsed = brute_force(
            target, algo, max_len=args.max_len
        )

    print()
    if result:
        print(f"  CRACKED! Password: {result}")
    else:
        print(f"  Password not found.")
    print(f"  Attempts: {attempts:,} | Time: {elapsed:.2f}s")
    if elapsed > 0:
        print(f"  Rate: {attempts / elapsed:,.0f} hashes/sec")
    print()


if __name__ == "__main__":
    main()
