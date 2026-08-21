# Aegis

[![CI](https://github.com/SA-Ark/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/SA-Ark/aegis/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

**A production-readiness audit CLI. Point it at a codebase or a live endpoint and it grades what would bite you first in production.**

The question Aegis answers: if this app shipped tonight, what's the thing that pages someone at 3 a.m.? Leaked credentials, unpinned dependencies, untested critical paths, rootful containers, missing security headers. It runs those checks and rolls them into one readiness score you can defend in a review.

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

Most audit tools answer one narrow question — just CVEs, or just lint, or just headers. But a real production rescue starts wider than that. What *categories* of risk exist here, how bad is each, and what do I fix first? Aegis bakes that triage into a tool: five weighted categories, severity-driven scoring, and a remediation line on every finding. It's the first hour of a readiness review, minus the consultant.

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

Every category starts at 100 and findings deduct by severity: Critical −40, High −15, Medium −6, Low −2, Info −0, floored at 0. The overall score is the weighted mean, so a single leaked credential visibly tanks the grade — which is exactly what you want it to do.

## Benchmarks

Measured with `/usr/bin/time` on an Intel i7-13700H (20 threads), warm page cache, release build:

| Target | Files walked | Wall time | Peak RSS |
|---|---|---|---|
| 1,600-file production monorepo (Rust + Next.js) | ~1,600 | 2.3 s | 20 MB |
| 130-source-file TypeScript app | ~350 | 0.3 s | 6 MB |
| This repository (self-scan) | ~25 | 0.06 s | 5 MB |

A probe of a live URL is a single GET, so it finishes in network RTT plus about a millisecond of analysis.

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

`scan` never touches the network — everything is judged from the worktree, so it's safe to run on client code under NDA. `probe` is read-only: one GET, no fuzzing, no auth, safe to point at production.

Secret detection is placeholder-aware. `${VAR}`, `<your-key>`, and `process.env...` assignments don't fire, because the goal is a report someone actually acts on, not a wall of false positives you learn to ignore.

And the heuristics are labeled as heuristics. Test debt is a risk signal, not a coverage report — each finding tells you what it actually measured, so you're never guessing what a number means.

## Limitations (the honest ones)

Secret detection is pattern-based, so it won't catch a novel token format — pair it with an entropy scanner if you want belt-and-braces. Dependency checks are static, with no advisory-database lookups; that's deliberate, since `scan` never goes to the network. Test-debt heuristics cover Rust, JS/TS, and Python, and nothing else.

## License

MIT — see [LICENSE](LICENSE).
