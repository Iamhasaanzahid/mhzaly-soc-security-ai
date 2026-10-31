# Pull request

## What changed

<!-- One paragraph. What behaviour is different after this PR? -->

## Why

<!-- Link the issue if there is one. -->

## Verification

<!-- How do you know this works? Paste the commands you ran. -->

```bash
python -m pytest
ruff check .
```

## Checklist

- [ ] New or changed behaviour is covered by a test
- [ ] Findings still pass the confidence gate (no new false-positive classes)
- [ ] No secrets, keys, webhook URLs or client data added to the repository
- [ ] `CHANGELOG.md` updated for user-visible changes
- [ ] Documentation updated where the behaviour is described
