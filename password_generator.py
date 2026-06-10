#!/usr/bin/env python3
"""
password_generator.py

A configurable password & passphrase generator.

Features:
    - Cryptographically secure randomness (uses the `secrets` module).
    - Random-character passwords with selectable character classes.
    - Optional guarantee that at least one char from each chosen class appears.
    - Option to exclude ambiguous characters (O/0, l/1/I, etc.).
    - Pronounceable / word-based passphrases (Diceware-style).
    - Shannon-entropy estimate and a simple strength label.
    - A small command-line interface.

Run:
    python3 password_generator.py --help
"""

from __future__ import annotations

import argparse
import math
import secrets
import string
from dataclasses import dataclass, field
from typing import List

# A small built-in word list keeps the file self-contained (no downloads needed).
# It is intentionally short; swap in a larger list (e.g. EFF Diceware) for production.
_WORDS: List[str] = [
    "able", "acid", "april", "argue", "atom", "badge", "baker", "blade",
    "blend", "brick", "brisk", "cabin", "candle", "cedar", "chalk", "cliff",
    "clover", "comet", "coral", "crisp", "dawn", "delta", "dune", "ember",
    "fable", "falcon", "fern", "flint", "frost", "garden", "glade", "globe",
    "grove", "harbor", "hazel", "ivory", "jewel", "kayak", "lagoon", "lantern",
    "ledge", "lunar", "maple", "marsh", "meadow", "mint", "noble", "oasis",
    "onyx", "opal", "orbit", "otter", "pearl", "pebble", "pine", "plume",
    "quartz", "quill", "raven", "ridge", "river", "rust", "saffron", "sage",
    "salt", "shore", "slate", "spruce", "stork", "summit", "talon", "tide",
    "timber", "topaz", "tulip", "umber", "valley", "vault", "vine", "willow",
    "wren", "yarrow", "zenith", "zephyr",
]

AMBIGUOUS = set("O0oI1lL5S2Z8B|`'\"{}[]()/\\")


@dataclass
class PasswordPolicy:
    """Describes which character classes to draw from and constraints to enforce."""

    length: int = 16
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    require_each_class: bool = True
    symbols: str = field(default="!@#$%^&*-_=+?")

    def pools(self) -> List[str]:
        """Return the list of non-empty character pools selected by this policy."""
        pools: List[str] = []
        if self.use_lower:
            pools.append(string.ascii_lowercase)
        if self.use_upper:
            pools.append(string.ascii_uppercase)
        if self.use_digits:
            pools.append(string.digits)
        if self.use_symbols:
            pools.append(self.symbols)

        if self.exclude_ambiguous:
            cleaned = []
            for pool in pools:
                filtered = "".join(c for c in pool if c not in AMBIGUOUS)
                if filtered:
                    cleaned.append(filtered)
            pools = cleaned
        return pools


def generate_password(policy: PasswordPolicy) -> str:
    """Generate a single password according to `policy`.

    Raises:
        ValueError: if no character class is enabled, the length is too small,
            or required-each-class cannot be satisfied for the given length.
    """
    pools = policy.pools()
    if not pools:
        raise ValueError("At least one character class must be enabled.")
    if policy.length < 1:
        raise ValueError("Length must be at least 1.")
    if policy.require_each_class and policy.length < len(pools):
        raise ValueError(
            f"Length {policy.length} is too short to include one character "
            f"from each of the {len(pools)} selected classes."
        )

    all_chars = "".join(pools)

    if policy.require_each_class:
        # Guarantee one char from each pool, then fill the rest from the union.
        chars = [secrets.choice(pool) for pool in pools]
        chars += [secrets.choice(all_chars) for _ in range(policy.length - len(pools))]
        # Shuffle so the guaranteed chars are not stuck at the front.
        _secure_shuffle(chars)
    else:
        chars = [secrets.choice(all_chars) for _ in range(policy.length)]

    return "".join(chars)


def _secure_shuffle(items: list) -> None:
    """In-place Fisher-Yates shuffle using cryptographically secure indices."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = False,
    add_number: bool = False,
) -> str:
    """Generate a Diceware-style passphrase from the built-in word list."""
    if word_count < 1:
        raise ValueError("word_count must be at least 1.")
    words = [secrets.choice(_WORDS) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    if add_number:
        phrase += separator + str(secrets.randbelow(100)).zfill(2)
    return phrase


def estimate_entropy_bits(password: str, pool_size: int) -> float:
    """Estimate entropy in bits assuming each char drawn uniformly from a pool.

    This is an upper-bound style estimate: entropy = length * log2(pool_size).
    """
    if pool_size <= 1 or not password:
        return 0.0
    return len(password) * math.log2(pool_size)


def strength_label(entropy_bits: float) -> str:
    """Map an entropy estimate to a coarse human-readable label."""
    if entropy_bits < 28:
        return "very weak"
    if entropy_bits < 36:
        return "weak"
    if entropy_bits < 60:
        return "reasonable"
    if entropy_bits < 128:
        return "strong"
    return "very strong"


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate secure passwords or passphrases.",
    )
    p.add_argument("-n", "--count", type=int, default=1,
                   help="How many to generate (default: 1).")
    p.add_argument("-l", "--length", type=int, default=16,
                   help="Password length in characters (default: 16).")
    p.add_argument("--no-lower", action="store_true", help="Exclude lowercase.")
    p.add_argument("--no-upper", action="store_true", help="Exclude uppercase.")
    p.add_argument("--no-digits", action="store_true", help="Exclude digits.")
    p.add_argument("--no-symbols", action="store_true", help="Exclude symbols.")
    p.add_argument("--exclude-ambiguous", action="store_true",
                   help="Drop easily confused characters (O/0, l/1, etc.).")
    p.add_argument("--allow-missing-class", action="store_true",
                   help="Do not force at least one char from each class.")
    p.add_argument("--passphrase", action="store_true",
                   help="Generate a word-based passphrase instead.")
    p.add_argument("--words", type=int, default=5,
                   help="Words per passphrase (default: 5).")
    p.add_argument("--separator", default="-", help="Passphrase separator.")
    p.add_argument("--capitalize", action="store_true",
                   help="Capitalize passphrase words.")
    p.add_argument("--add-number", action="store_true",
                   help="Append a random 2-digit number to the passphrase.")
    return p


def main(argv: List[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    try:
        for _ in range(max(1, args.count)):
            if args.passphrase:
                secret = generate_passphrase(
                    word_count=args.words,
                    separator=args.separator,
                    capitalize=args.capitalize,
                    add_number=args.add_number,
                )
                bits = estimate_entropy_bits(
                    "x" * args.words, len(_WORDS)
                )
            else:
                policy = PasswordPolicy(
                    length=args.length,
                    use_lower=not args.no_lower,
                    use_upper=not args.no_upper,
                    use_digits=not args.no_digits,
                    use_symbols=not args.no_symbols,
                    exclude_ambiguous=args.exclude_ambiguous,
                    require_each_class=not args.allow_missing_class,
                )
                secret = generate_password(policy)
                pool_size = sum(len(pool) for pool in policy.pools())
                bits = estimate_entropy_bits(secret, pool_size)

            print(f"{secret}\t(~{bits:.0f} bits, {strength_label(bits)})")
    except ValueError as exc:
        print(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
