# Aegis

[![CI](https://github.com/SA-Ark/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/SA-Ark/aegis/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

**Production readiness audit CLI — grade a codebase or a live endpoint the way a rescue engineer does on day one.**

Aegis answers one question fast: *if this app shipped to production tonight, what bites you first?* It runs the
checks that actually page people at 3 a.m. — leaked credentials, unpinned supply chains, untested critical paths,
rootful containers, naked HTTP headers — and compresses them into a single defensible readiness score.

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

## Why

Most "audit" tooling answers a narrow question (just CVEs, just lint, just headers). A production rescue starts
wider: *what categories of risk exist, how bad is each, and what do I fix first?* Aegis encodes that triage as a
tool — five weighted categories, severity-driven scoring, and a remediation line on every finding. It is the
first-hour instrument of a production-readiness consultation, distilled into a binary.

## Architecture

```
                       ┌──────────────────────────────────────────┐
                       │                 aegis CLI                │
                       └─────────┬───────────────────┬────────────┘
                                 │                   │
                          aegis scan <path>    aegis probe <url>
                                 │                   │
                 ┌───────────────┴──────────┐   single GET (ureq, 15s timeout)
                 │   one filesystem walk    │        │
                 │ (skips .git, node_modules│   response headers + TLS + timing
                 │  target, dist, vendored) │        │
                 └───────────────┬──────────┘        │
        ┌────────────┬───────────┼────────────┐      │
        ▼            ▼           ▼            ▼      ▼
   ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐
   │ secrets │ │   deps   │ │test debt│ │ config  │ │ transport │
   │ 8 rule  │ │ npm/cargo│ │ tests vs│ │ env/CI/ │ │ HSTS/CSP/ │
   │ classes │ │ /pip     │ │ src,TODO│ │ docker/ │ │ cookies/  │
   │         │ │ pinning  │ │ unwraps │ │ CORS    │ │ leaks     │
   └────┬────┘ └────┬─────┘ └────┬────┘ └────┬────┘ └─────┬─────┘
        └───────────┴─────┬──────┴────────────┘            │
                          ▼                                ▼
              ┌────────────────────────────────────────────────┐
              │  Report: findings → category scores → weighted │
              │  overall (secrets 30% · deps/tests/config 20%  │
              │  · CI 10%) → text / JSON / Markdown            │
              └────────────────────────────────────────────────┘
```

## What it checks

| Category | Checks |
|---|---|
| **Secrets & Credentials** (30%) | AWS keys, GitHub/Slack/Stripe tokens, private key blocks, JWTs, connection strings with inline passwords, hardcoded credential assignments (placeholder-aware) |
| **Dependency Hygiene** (20%) | Missing lockfiles, wildcard/`latest` versions, plaintext-HTTP packages, unpinned git deps, unpinned Python requirements |
| **Test Debt** (20%) | No-tests detection, test-to-source ratio, TODO/FIXME accumulation, `unwrap()`/`expect()` panic density (Rust), stray `console.log` (JS) |
| **Configuration** (20%) | Env files vs `.gitignore` coverage, rootful Dockerfiles, `:latest` base images, wildcard CORS |
| **CI / Automation** (10%) | Presence of a CI pipeline (GitHub Actions / GitLab / Jenkins / CircleCI) |
| **Transport & Headers** (probe) | HTTPS enforcement, HSTS, CSP, nosniff, clickjacking protection, Referrer-Policy, cookie `Secure`/`HttpOnly`, server version disclosure, 5xx status, TTFB |

Scoring: each category starts at 100; findings deduct by severity (Critical −40, High −15, Medium −6, Low −2,
Info −0; floor 0). The overall score is the weighted mean — so a single leaked credential visibly tanks the
grade, exactly as it should.

## Benchmarks

Measured with `/usr/bin/time` on an Intel i7-13700H (20 threads), warm page cache, release build:

| Target | Files walked | Wall time | Peak RSS |
|---|---|---|---|
| 1,600-file production monorepo (Rust + Next.js) | ~1,600 | 2.3 s | 20 MB |
| 130-source-file TypeScript app | ~350 | 0.3 s | 6 MB |
| This repository (self-scan) | ~25 | 0.06 s | 5 MB |

Single GET probe of a live URL completes in network RTT + ~1 ms of analysis.

## Quickstart

```bash
# build
cargo build --release

# audit a codebase
./target/release/aegis scan ./path/to/project

# audit a live endpoint
./target/release/aegis probe https://your-app.example

# machine-readable output + CI gate (exit 1 below threshold)
aegis scan . --format json --fail-under 80
aegis scan . --format markdown > AUDIT.md
```

Exit codes: `0` pass, `1` score below `--fail-under`, `2` execution error.

## Using it as a CI gate

```yaml
- name: Production readiness gate
  run: aegis scan . --fail-under 75
```

## Design notes

- **Zero network on `scan`.** Everything is judged from the worktree; safe to run on client code under NDA.
- **Read-only `probe`.** One GET, no fuzzing, no auth — safe against production.
- **Placeholder-aware secret detection.** `${VAR}`, `<your-key>`, `process.env...` assignments don't fire;
  the goal is a report a human acts on, not a wall of false positives.
- **Heuristics labeled as heuristics.** Test debt is a *risk signal*, not a coverage report — the README of a
  finding tells you what it measured.

## Limitations (honest ones)

- Secret detection is pattern-based; it will not catch novel token formats (pair with entropy scanners for
  belt-and-braces).
- Dependency checks are static — no advisory-database lookups (by design: `scan` never touches the network).
- Language coverage for test-debt heuristics: Rust, JS/TS, Python.

## License

MIT — see [LICENSE](LICENSE).
