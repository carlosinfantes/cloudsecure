# Contributing to CloudSecure

## Prerequisites

- Node.js 18+
- Python 3.12+
- Docker
- AWS CLI configured
- [pre-commit](https://pre-commit.com/)
- [gitleaks](https://github.com/gitleaks/gitleaks)

## Setup

### 1. Install pre-commit hooks (mandatory)

```bash
brew install pre-commit gitleaks
pre-commit install
pre-commit install --hook-type pre-push
```

### 2. Install dependencies and build

```bash
make install   # Install CDK + Python dependencies
make layer     # Build Lambda shared layer (uses Docker if available, pip fallback)
```

## Secret Scanning Policy

Pre-commit hooks enforce the following on every commit:

- **gitleaks** scans for AWS keys, tokens, passwords, and high-entropy strings
- **Custom hooks** block:
  - 12-digit AWS account IDs (use `123456789012` as placeholder)
  - Internal email addresses
  - Organization-specific identifiers
- **Large files** over 500KB are blocked (no binaries in the repo)
- **Private keys** (PEM headers) are blocked

If a hook blocks your commit, fix the issue before committing. Never use `--no-verify` to bypass hooks.

## Pull Request Checklist

- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] No real AWS account IDs or credentials in any file
- [ ] Lambda layer vendored files are NOT committed (`lambdas/layer/python/`)
- [ ] Tests pass (`cd lambdas && pytest`)
- [ ] CDK synthesizes successfully (`cd infrastructure && npm run build && npx cdk synth`)

## Commits

Use conventional commit messages: `Fix ...`, `Add ...`, `Update ...`, `Refactor ...`.

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production releases (protected, no direct commits) |
| `dev` | Active development |
| `feature/*` | Feature branches (merge to `dev`) |
