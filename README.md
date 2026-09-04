# C8 — Diffie-Hellman Demo

Demonstrates the Diffie-Hellman key exchange, a man-in-the-middle attack, and parameter analysis.

## Overview

This project implements and demonstrates:
- Authenticated-style DH key exchange (RFC 3526 Group 14, 2048-bit)
- Real key agreement using `pow` modular exponentiation
- A man-in-the-middle attack demonstration
- Parameter analysis (prime bit-length, generator checks)
- A small-prime worked example for education

## Features

- **Key exchange**: private/public key generation, shared secret derivation
- **KDF**: SHA-256 session key derivation
- **MITM demo**: shows how interception breaks key agreement
- **Analysis**: prime/generator property checks
- **CSPRNG**: uses `secrets` for private keys

## Usage

```bash
python3 dh.py
```

## Example Output

```
=== Diffie-Hellman Key Exchange ===
p (prime, 2048 bits): ...FFFFFFFF
g (generator): 2

Private keys (secret):
  a (Alice): 256 bits
  b (Bob):   256 bits

Shared secrets:
  s_a == s_b? True
  Session key (SHA256): 0f2b...
```

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
