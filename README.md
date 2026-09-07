# C8 — Diffie-Hellman Demo

Demonstrates the Diffie-Hellman key exchange, a man-in-the-middle attack, and parameter analysis.

## Overview

This project implements and demonstrates:
- Authenticated-style DH key exchange (RFC 3526 Group 14, 2048-bit)
- Real key agreement using `pow` modular exponentiation
- A man-in-the-middle attack demonstration
- Parameter analysis (Miller-Rabin primality, safe-prime check, generator order)
- A small-prime worked example for education

## Features

- **Key exchange**: private/public key generation, shared secret derivation
- **KDF**: SHA-256 session key derivation
- **MITM demo**: shows how interception breaks key agreement
- **Analysis**: prime/generator property checks with a statistical generator-order
  classification (primitive root vs prime-order subgroup vs order-2)
- **CSPRNG**: uses `secrets` for private keys
- **CLI**: plain render, `--json`, `--output`, `--run`, custom `--p`/`--g`

## Installation

```bash
# No external dependencies required
# Uses only Python standard library
```

## Usage

```bash
# Run the full demo (writes a report, exit 0)
python3 dh.py

# JSON report to file
python3 dh.py --json --output reports/dh.json

# Classic text-mode key exchange
python3 dh.py --run

# Analyze custom parameters
python3 dh.py --p 23 --g 5

# Use in code
from dh import dh_exchange, mitm_demo, analyze_parameters
report = dh_exchange()
print(report['session_key'])
```

## Example Output

```
=== Diffie-Hellman Demo ===
RFC 3526 Group 14 (2048-bit) key exchange:
  p bits: 2048, g: 2
  Alice pub: ...557e2aeea178
  Bob pub:   ...b8fd7d4f32be
  shared secrets equal: True
  session key (SHA-256): 5a0156b1...

=== Man-in-the-Middle ===
  Alice & Mallory agree: True
  Bob & Mallory agree:   True
  Alice & Bob SAME key:  False

=== Parameter Analysis ===
  p bits: 2048, probable prime: True, safe prime: True
  generator g=2: True (g generates the prime-order subgroup (order q, 2047 bits))
  smallest usable? p>=1024 bits: True
```

Note: for RFC 3526 primes (which are `7 mod 8`), generator 2 is a quadratic
residue, so it generates the prime-order subgroup of quadratic residues rather
than the full group — the check reports this correctly and accepts it.

## Live Lab Test Plan

| Step | Command | Expected result |
|------|---------|-----------------|
| 1 | `python3 dh.py` | exchange shown, `shared secrets equal: True`, exit 0 |
| 2 | `python3 dh.py` (MITM section) | `Alice & Bob SAME key: False`, Mallory agrees with both |
| 3 | `python3 dh.py` (analysis section) | p 2048 bits, probable prime True, safe prime True, generator ok |
| 4 | `python3 dh.py --p 23 --g 5` | analysis flags small prime (`p>=1024 bits: False`) |
| 5 | `python3 dh.py --json --output reports/dh.json` | valid JSON report |
| 6 | `python3 dh.py --run` | classic text-mode exchange + SHA256 session key |
| 7 | `python3 -m unittest discover -s tests` | 18 tests pass |

## Metrics

- 18 unit tests, all passing (`python3 -m unittest discover -s tests`).
- RFC 3526 Group 14 prime verified as a 2048-bit probable prime and safe prime;
  generator 2 validated as generating the prime-order subgroup (order q, 2047 bits).
- MITM demo deterministically shows two independent agreement pairs
  (Alice↔Mallory, Bob↔Mallory) while Alice/Bob never share a key.
- Fully deterministic small-prime worked example (`p=23, g=5, a=6, b=15` → shared secret 2).
- Pure standard-library implementation, no third-party packages.

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
