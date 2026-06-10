#!/usr/bin/env python3
"""Tests for password_generator.py. Run with: python3 test_password_generator.py"""

import string
import unittest

from password_generator import (
    AMBIGUOUS,
    PasswordPolicy,
    estimate_entropy_bits,
    generate_passphrase,
    generate_password,
    strength_label,
)


class TestPasswordGenerator(unittest.TestCase):
    def test_default_length(self):
        pw = generate_password(PasswordPolicy(length=20))
        self.assertEqual(len(pw), 20)

    def test_only_digits(self):
        policy = PasswordPolicy(
            length=12, use_lower=False, use_upper=False,
            use_digits=True, use_symbols=False,
        )
        pw = generate_password(policy)
        self.assertTrue(all(c in string.digits for c in pw))

    def test_require_each_class(self):
        policy = PasswordPolicy(length=8, require_each_class=True)
        for _ in range(200):  # probabilistic guarantee check
            pw = generate_password(policy)
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in policy.symbols for c in pw))

    def test_exclude_ambiguous(self):
        policy = PasswordPolicy(length=40, exclude_ambiguous=True)
        for _ in range(50):
            pw = generate_password(policy)
            self.assertFalse(any(c in AMBIGUOUS for c in pw))

    def test_no_class_raises(self):
        policy = PasswordPolicy(
            use_lower=False, use_upper=False,
            use_digits=False, use_symbols=False,
        )
        with self.assertRaises(ValueError):
            generate_password(policy)

    def test_too_short_for_each_class_raises(self):
        policy = PasswordPolicy(length=2, require_each_class=True)
        with self.assertRaises(ValueError):
            generate_password(policy)

    def test_passphrase_word_count(self):
        phrase = generate_passphrase(word_count=4, separator="-")
        self.assertEqual(len(phrase.split("-")), 4)

    def test_passphrase_with_number(self):
        phrase = generate_passphrase(word_count=3, add_number=True)
        parts = phrase.split("-")
        self.assertEqual(len(parts), 4)
        self.assertTrue(parts[-1].isdigit())

    def test_entropy_and_label(self):
        self.assertEqual(estimate_entropy_bits("", 70), 0.0)
        bits = estimate_entropy_bits("abcdefghij", 70)
        self.assertGreater(bits, 0)
        self.assertEqual(strength_label(10), "very weak")
        self.assertEqual(strength_label(200), "very strong")

    def test_randomness_differs(self):
        policy = PasswordPolicy(length=24)
        a = generate_password(policy)
        b = generate_password(policy)
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
