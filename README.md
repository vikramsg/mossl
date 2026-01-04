# ssl.mojo

## Goal
Implement a **pure Mojo** TLS 1.3 client stack sufficient to perform HTTPS GETs via `lightbug_http`.

## Status
- Stage 1 (SHA-256 / HMAC-SHA256 / HKDF): **implemented and tested**
- Stages 0, 2–5: **pending** (see `docs/spec.md`)

## Layout
```
crypto/          Stage 1 crypto primitives (pure Mojo)
docs/            Roadmap and specs
specs/           Quint specs
tests/           Mojo tests (test_*.mojo)
scripts/         Usage scripts
```

## Commands
```
# Run Stage 1 Mojo tests (grouped)
pixi run test-stage1

# Run Stage 1 Quint spec tests
pixi run test-specs

# Run everything tracked in pixi.toml
pixi run test-all
```

## Testing Note (Mojo 0.25.6)
Mojo 0.25.6 does **not** include the `TestSuite` test runner, so tests run via
`mojo run` instead of `mojo test`. Once `mojo == 0.25.7` is available in the
channel, the tests should be migrated to `TestSuite`.

## Setup
We use Pixi for dependencies.

```
curl -fsSL https://pixi.sh/install.sh | bash
echo 'eval "$(pixi completion --shell zsh)"' >> ~/.zshrc
pixi shell
```
