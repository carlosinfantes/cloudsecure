# Contributing to CloudSecure

## Prerequisites

- Node.js 20+ (24 is what CI uses)
- Python 3.12+
- Docker or Podman
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
make layer     # Build Lambda shared layer (Docker or Podman; pip fallback)
```

> Without a container runtime the layer is built with the host's wheels, which
> only works if the host is Linux x86_64 on Python 3.12. On macOS or ARM, use
> Docker or Podman or every Lambda will fail to import its dependencies.

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

## Testing & Validation

### Running tests

```bash
make test    # Run CDK (jest) + Python (pytest) tests
make lint    # Check Python code style (ruff + black)
```

Or individually:

```bash
cd lambdas && python -m pytest tests/ -v              # Python unit tests
cd infrastructure && npm test                          # CDK snapshot tests
cd lambdas && ruff check . && black --check .          # Linting
```

### What gets tested

| Area | Tool | Coverage |
|------|------|----------|
| Shared models (Assessment, Finding, CRF) | pytest | `lambdas/tests/test_models.py`, `test_crf_models.py` |
| AWS client (STS AssumeRole, regions) | pytest | `lambdas/tests/test_aws_client.py` |
| Analyzers, API handlers, Prowler parsing | pytest, moto where the AWS response shape matters | `lambdas/tests/` |
| CLI (endpoint resolution, commands) | pytest | `cli/tests/` |
| CDK stack synthesis | jest + `cdk synth` in CI | `infrastructure/test/` |
| Python code style | ruff + black | All files in `lambdas/` |
| Secrets in code | gitleaks + custom hooks | Every commit (pre-commit) |
| Secrets in CI | gitleaks GitHub Action | Every push and PR |

### What runs automatically

**On every commit** (pre-commit hooks):
- Trailing whitespace, end-of-file, YAML/JSON/TOML validation
- Secret scanning (gitleaks)
- Block real AWS account IDs, internal emails, private keys
- Block commits directly to `main`
- Python formatting (ruff + black on `lambdas/`)

**On every push/PR** (GitHub Actions):
- gitleaks secret scan (`.github/workflows/secrets-scan.yml`)
- Lambda tests and lint, with coverage measured over every package and a 50%
  floor (`.github/workflows/ci.yml`)
- CLI tests on Python 3.10 and 3.13, with AWS access disabled
- CDK build, jest and `cdk synth`

Mock the AWS calls in unit tests. Prefer moto when the shape of the AWS
response is what the code depends on: mocks that return a shape AWS never
returns are how several bugs reached production with CI green.

## Pull Request Checklist

- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] No real AWS account IDs or credentials in any file
- [ ] Lambda layer vendored files are NOT committed (`lambdas/layer/python/`)
- [ ] CDK synthesizes successfully (`make synth`)
- [ ] No AI attribution or co-author trailers in commits, PR descriptions or
      code comments

## Commits

Use conventional commit messages: `Fix ...`, `Add ...`, `Update ...`, `Refactor ...`.

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production releases (protected, no direct commits) |
| `dev` | Active development |
| `feature/*` | Feature branches (merge to `dev`) |
