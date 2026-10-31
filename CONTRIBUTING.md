# Contributing

Thanks for taking the time to improve the platform. This document describes the
shortest path from a checkout to a merged change.

## Development setup

```bash
git clone https://github.com/Iamhasaanzahid/mhzaly-soc-security-ai.git
cd mhzaly-soc-security-ai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pre-commit install          # optional, but recommended
```

Run the dashboard:

```bash
streamlit run app.py
```

Run the quality gates (these are exactly what CI runs):

```bash
python -m pytest
ruff check .
```

## Design principles

These are not stylistic preferences — they are the reason the platform exists.

1. **Precision over volume.** A finding that cannot be reproduced is worse than
   no finding. New checks must attach an evidence block that `core/confidence.py`
   can score, and must include a false-positive test.
2. **Verification before reporting.** Status codes are not evidence. Sensitive
   paths are only reported after soft-404 calibration and a content-signature
   match (`core/hunter.py`).
3. **Human voice.** Reports are written for an engineer reading them at 2am.
   `core/reporter.py` owns the prompt and the `humanize()` pass; do not add
   marketing adjectives or emoji to generated text.
4. **Fail closed on scope.** Targets that resolve to private, loopback or
   metadata addresses are refused (`core/connectors.assert_public_host`).

## Commit style

`type(scope): imperative summary` — for example:

```
feat(hunter): verify .git/config by content signature
fix(scheduler): run as module so `core` is importable in CI
docs(readme): document the confidence gate
```

Types in use: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`.

## Tests

- Every bug fix gets a regression test.
- Every new finding kind gets a scoring test in `tests/test_confidence.py`.
- Network code must be testable without the network: extract the parsing and
  decision logic into a pure function (see `hunter.grade_security_headers`,
  `hunter.leak_signature`, `hunter.is_soft_404`).

## Security

Do not open a public issue for a vulnerability in this repository. See
[SECURITY.md](SECURITY.md) for the private reporting process.

Never commit secrets. The repository is configured to load credentials from
environment variables or Streamlit secrets, never from tracked files.

## License

By contributing you agree that your contribution is licensed under the MIT
License (see [LICENSE](LICENSE)).
