# Contributing to PipeShield

Thanks for your interest in contributing! PipeShield is a DevSecOps scanner and
every improvement to detection coverage directly helps secure CI/CD pipelines.

## Development Setup

```bash
git clone https://github.com/Voobrazhenie21-lab/pipeshield.git
cd pipeshield

uv sync --extra dev
uv run pytest -v

# or: pip install -e ".[dev]" && pytest -v
```

## Adding a New Check

1. Implement the check in `src/pipeshield/` following the existing structure.
2. Add positive **and** negative test cases to `tests/` (a check that never
   fires on clean input is as important as one that catches bad input).
3. Add example fixtures to `examples/`.
4. Document the check in the README with severity, rationale, and remediation.

## Pull Request Checklist

- [ ] `pytest -v` passes locally.
- [ ] New checks have test coverage (true-positive and false-positive cases).
- [ ] README updated for user-facing changes.
- [ ] Example secrets in tests/fixtures use obviously-fake values
      (`AKIAIOSFODNN7EXAMPLE`-style), never real credentials.
- [ ] Commit messages follow conventional style (`feat:`, `fix:`, `docs:`, `ci:`).

## Ideas for Future Contributions

- SARIF output for GitHub code scanning integration.
- Pre-commit hook packaging.
- Baseline file support (ignore known/accepted findings).
