# Security Guide

This generator is designed for local use on your own computer.

## Good Habits

- Generate a different password for every account.
- Use a password manager to store passwords.
- Prefer the `strong` or `maximum` preset for important accounts.
- Use a passphrase when you need something easier to remember.
- Do not share passwords through chat, email, screenshots, or public documents.

## Randomness

The app uses Python's `secrets` module instead of `random`, because `secrets` is designed for passwords and tokens.

## Clipboard

Clipboard copy is optional. If you copy a password, paste it soon and avoid leaving it in your clipboard longer than needed.
