# Password Generator

A simple, secure password and passphrase generator for everyday use.

It uses Python's built-in `secrets` module, which is designed for cryptographic randomness. No extra packages are required.

## Features

- Easy, strong, and maximum password presets
- Optional passphrases that are easier to remember
- Avoids confusing characters like `O/0` and `l/1` in beginner-friendly presets
- Optional clipboard copy when your system supports it
- Strength estimate for every generated password
- Interactive mode for users who do not want to remember command flags

## Quick Start

Download the project, then run the generator:

- Windows: double-click `run_password_generator.bat`
- Mac/Linux: open a terminal in the folder and run:

```bash
python password_generator.py
```

By default, the app opens a simple interactive menu.

## Command Examples

Generate one strong password without the menu:

```bash
python password_generator.py --preset strong
```

Generate an easy-to-read password:

```bash
python password_generator.py --preset basic
```

Generate a memorable passphrase:

```bash
python password_generator.py --passphrase --words 5 --capitalize --add-number
```

Copy the generated password to your clipboard when available:

```bash
python password_generator.py --copy
```

Print only the password, useful for scripts:

```bash
python password_generator.py --plain
```

## Presets

| Preset | Best for | Default |
| --- | --- | --- |
| `basic` | Everyday accounts where readability matters | 12 characters, letters and numbers |
| `memorable` | Longer passwords that avoid symbols | 16 characters, letters and numbers |
| `strong` | Important accounts like email, banking, cloud, and school | 18 characters, symbols included |
| `maximum` | Password managers and high-value accounts | 24 characters, symbols included |

## Examples

Generate 5 strong passwords:

```bash
python password_generator.py --count 5
```

Generate a 20-character password without symbols:

```bash
python password_generator.py --length 20 --no-symbols
```

Generate a password without confusing characters:

```bash
python password_generator.py --exclude-ambiguous
```

## Run Tests

```bash
python -m unittest -v
```

## Safety Notes

- Use a different password for every account.
- Store passwords in a password manager when possible.
- Use passphrases when you need something memorable.
- Do not send passwords through chat, email, or screenshots.
