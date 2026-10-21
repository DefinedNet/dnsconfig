# AGENTS.md

Operational notes for this repository.

## Scope

`dnsconfig` (module `github.com/DefinedNet/dnsconfig`) is a Go library for
configuring system DNS on macOS and Windows only. The root package is the
public API. Everything under `internal/cmd/` is test scaffolding: `dnsconfigctl`
exercises the API and supplies the smoke harness's sentinel, query, and
watcher commands, and has no CLI surface to preserve. API stability, godoc,
and exhaustive coverage apply to the library.

## Where behavior is documented

Do not restate these here; fix them at the source.

- `doc.go` is the normative package contract. Identifier godoc, especially
  on Set, Clear, Close, Config, Options, Status, and the error sentinels,
  carries the per-call detail.
- `docs/design.md` explains why the contract is what it is, including the
  macOS conflict rules and the Windows NRPT store selection.
- `CONTRIBUTING.md` has the code tour, the build, test, and lint commands,
  and the formatting rules.
- `docs/testing.md` describes the test layers and the smoke harness. The
  matrices in `internal/cmd/smoketest/matrix_macos.go` and `matrix_win.go`
  name the rows, the `runner_*.go` files hold their assertions, and the
  workflows under `.github/workflows/` say which OS runs which rows.
- `docs/README.md` indexes the rest. `docs/faq.md` answers end with the
  evidence behind them.

## Conventions

Beyond CONTRIBUTING:

- No emojis and no backwards-compatibility shims. Change unreleased APIs
  cleanly.
- A nil Options.Logger discards output; never fall back to slog.Default().
- Comments and docs explain why, not what changed. Describe current
  behavior, verify every claim against the code, and keep prose concise and
  ASCII.
- No experiment records in the tree. Measurements go in issue or PR
  comments.

## Smoke harness

The harness changes the current machine's DNS. Run live rows only on
disposable CI runners, never on a development machine. Rows are M1-M7 on
macOS and W1-W7 on Windows and run sequentially because they share the
host's DNS. Harness files that both hosts must compile use a `_win.go`
suffix, not `_windows.go`.
