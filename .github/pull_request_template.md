## What does this change?

<!-- Problem first, then the approach. -->

## Type

- [ ] Bug fix
- [ ] New plugin / capability
- [ ] Documentation
- [ ] CI / tooling
- [ ] Security hardening

## Checklist

- [ ] `for t in tests/test_*.py; do python3 "$t" || break; done` passes
- [ ] `make && make test` passes (if `src/sentineld.c` touched)
- [ ] No `shell=True` or `system()` introduced
- [ ] No hardcoded `~/.sentinel`; state goes through `sentinel/core/paths.py`
- [ ] Tests sandbox `SENTINEL_HOME` and do not touch the real state directory
- [ ] New third-party engines added to `LICENSES.md` with license + method
- [ ] `README.md` and `CHANGELOG.md` updated if behaviour or flags changed

## Verification

<!-- Paste real command output for behavioural claims. -->

```
```
