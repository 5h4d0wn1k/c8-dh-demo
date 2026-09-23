> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C8 — Diffie-Hellman Key-Exchange Demo

Interactive Diffie-Hellman crypto demo: RFC 3526 Group 14 (2048-bit) key exchange with SHA-256 session keys, a man-in-the-middle simulation, and DH parameter analysis — pure Python stdlib.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/c8-dh-demo.svg)](https://github.com/5h4d0wn1k/c8-dh-demo)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c8-dh-demo.svg)](https://github.com/5h4d0wn1k/c8-dh-demo)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/c8-dh-demo.svg)](https://github.com/5h4d0wn1k/c8-dh-demo)

## Why

Diffie-Hellman is the foundation of secure key agreement — and its textbook images hide exactly where it fails: unbounded parameters and missing authentication. C8 makes both visible in code. It runs a real 2048-bit exchange (RFC 3526 Group 14), derives a SHA-256 session key, demonstrates how a MITM quietly negotiates separate keys with both parties, and analyzes a prime/generator pair (Miller–Rabin primality, safe-prime check, generator-order classification). A small-prime worked example makes every step followable by hand.

## Features

- **Real key exchange** — RFC 3526 Group 14 (2048-bit) via `pow` modular exponentiation, `secrets`-based private keys
- **SHA-256 KDF** — deterministic session-key derivation from the shared secret
- **MITM simulation** — shows Alice↔Mallory and Bob↔Mallory agreeing while Alice↔Bob never share a key
- **Parameter analysis** — Miller–Rabin primality, safe-prime check, generator-order classification (primitive root / prime-order subgroup / order-2)
- **Custom `--p` / `--g`** — analyze your own parameters, flag weak primes
- **JSON output** — `--json --output` for scripting and labs

## Quickstart

```bash
# Full demo (writes a report, exit 0)
python3 dh.py

# JSON report to file
python3 dh.py --json --output reports/dh.json

# Classic text-mode exchange
python3 dh.py --run

# Analyze custom parameters
python3 dh.py --p 23 --g 5

# Use as a library
from dh import dh_exchange, mitm_demo, analyze_parameters
report = dh_exchange()

# Unit tests (18)
python3 -m unittest discover -s tests
```

## Project structure

- `dh.py` — exchange, MITM demo, parameter analysis and CLI
- `tests/` — 18 unit tests over the exchange, MITM and analysis paths

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New attacks, parameter checks and test vectors are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); the demo must stay offline and educational.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized crypto research only.