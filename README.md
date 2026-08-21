# aegis

[![Crates.io](https://img.shields.io/crates/v/aegis-audit.svg)](https://crates.io/crates/aegis-audit)
[![Docs.rs](https://img.shields.io/docsrs/aegis-audit)](https://docs.rs/aegis-audit)
[![CI](https://github.com/SA-Ark/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/SA-Ark/aegis/actions/workflows/ci.yml)
[![Downloads](https://img.shields.io/crates/d/aegis-audit.svg)](https://crates.io/crates/aegis-audit)
[![License](https://img.shields.io/crates/l/aegis-audit.svg)](LICENSE)

aegis audits a codebase or a live URL for production-readiness — leaked secrets, vulnerable dependencies, untested critical paths, and unsafe config — in one command.

Point it at a directory or an endpoint and it grades what would bite you first in production, then rolls the findings into one readiness score you can defend in a review. It's the first hour of a rescue, minus the consultant.

## Demo

```
AEGIS — production readiness report
target: ./acme-api

  Secrets & Credentials    [######----]  60  D
  Dependency Hygiene       [#######---]  73  C
  Test Debt                [########--]  79  C
  Configuration            [#####-----]  52  F
  CI / Automation          [########--]  85  B

  OVERALL: 67/100 (grade D)

  [CRITICAL] AWS access key ID detected
             at src/config.js:3
             fix: Rotate the credential immediately, then move it to a secret manager ...
```

Every category starts at 100 and findings deduct by severity: Critical −40, High −15, Medium −6, Low −2, Info −0, floored at 0. The overall is a weighted mean (secrets 30% · deps/tests/config 20% each · CI 10%), so a single leaked credential visibly tanks the grade — which is exactly what you want it to do.

## What it checks

| Category | Checks |
|---|---|
| **Secrets & Credentials** (30%) | AWS keys, GitHub/Slack/Stripe tokens, private key blocks, JWTs, connection strings with inline passwords, hardcoded credential assignments (placeholder-aware) |
| **Dependency Hygiene** (20%) | Missing lockfiles, wildcard/`latest` versions, plaintext-HTTP packages, unpinned git deps, unpinned Python requirements |
| **Test Debt** (20%) | No-tests detection, test-to-source ratio, TODO/FIXME accumulation, `unwrap()`/`expect()` panic density (Rust), stray `console.log` (JS) |
| **Configuration** (20%) | Env files vs `.gitignore` coverage, rootful Dockerfiles, `:latest` base images, wildcard CORS |
| **CI / Automation** (10%) | Presence of a CI pipeline (GitHub Actions / GitLab / Jenkins / CircleCI) |
| **Transport & Headers** (probe) | HTTPS enforcement, HSTS, CSP, nosniff, clickjacking protection, Referrer-Policy, cookie `Secure`/`HttpOnly`, server version disclosure, 5xx status, TTFB |

## Installation

```bash
cargo install aegis-audit    # installs the `aegis` binary
```

Or build from source with `cargo build --release`.

## Usage

```bash
# audit a codebase
aegis scan ./path/to/project

# audit a live endpoint
aegis probe https://your-app.example

# machine-readable output + CI gate (exit 1 below threshold)
aegis scan . --format json --fail-under 80
aegis scan . --format markdown > AUDIT.md
```

`scan` never touches the network — everything is judged from the worktree, so it's safe to run on client code under NDA. `probe` is read-only: one GET, no fuzzing, no auth, safe to point at production. Wire it into CI as a gate:

```yaml
- name: Production readiness gate
  run: aegis scan . --fail-under 75
```

## Exit codes

`0` pass, `1` score below `--fail-under`, `2` execution error.

## Benchmarks

Measured with `/usr/bin/time` on an Intel i7-13700H (20 threads), warm page cache, release build:

| Target | Files walked | Wall time | Peak RSS |
|---|---|---|---|
| 1,600-file production monorepo (Rust + Next.js) | ~1,600 | 2.3 s | 20 MB |
| 130-source-file TypeScript app | ~350 | 0.3 s | 6 MB |
| This repository (self-scan) | ~25 | 0.06 s | 5 MB |

A probe of a live URL is a single GET, so it finishes in network RTT plus about a millisecond of analysis.

## Configuration

Secret detection is placeholder-aware: `${VAR}`, `<your-key>`, and `process.env...` assignments don't fire, because the goal is a report someone acts on, not a wall of false positives you learn to ignore. The heuristics are labeled as heuristics — test debt is a risk signal, not a coverage report, and each finding tells you what it actually measured.

Some limits, stated plainly. Secret detection is pattern-based, so it won't catch a novel token format — pair it with an entropy scanner if you want belt-and-braces. Dependency checks are static, with no advisory-database lookups, because `scan` never goes to the network. Test-debt heuristics cover Rust, JS/TS, and Python, and nothing else.

## License

MIT — see [LICENSE](LICENSE).
