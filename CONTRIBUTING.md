# Contributing

Thanks for your interest. This project is organized in phases; each phase lands
behind a review gate.

## Development setup

```bash
make setup   # editable install + pytest
make test    # run the suite
make demo    # end-to-end vault seal/open
```

Requires Python 3.11+. Phase 1 has no third-party runtime dependencies.

## Ground rules

- **Never present the toy RSA in `cryptolayer/classical.py` as secure.** It is
  broken by design. Any code path that could be mistaken for production crypto
  must be clearly labeled.
- Keep the application (`maze/`) free of any direct algorithm imports — it must
  talk only to `cryptolayer` by algorithm name. Preserving that seam is the
  entire point of the project.
- New algorithms are added by implementing `LockBox` and calling `register(...)`
  in `cryptolayer/registry.py`. No application changes should be required.
- Add tests for anything you add; `make test` must stay green.

## Commit / release

Semantic version tags (`v1.0.0`, `v1.1.0`, ...). Each phase completion is tagged.
