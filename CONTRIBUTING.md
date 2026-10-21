# Contributing to dnsconfig

Start with the [README](README.md) and [package overview](doc.go).
The public library is the root package. Everything under `internal/cmd/` is test
scaffolding, with no production CLI compatibility contract.

## Code tour

1. [Config](config.go), [Options](options.go), [Status](status.go), and
   [errors](errors.go) define the caller's inputs and observations.
2. [Manager](manager.go) owns goals, retries, and shutdown. Its worker reads
   and updates bookkeeping under a mutex, releasing it during backend calls
   so `Set`, `Clear`, and `Status` do not wait for an attempt.
3. The [backend contract](internal/backend/backend.go) defines one-shot
   Set and Clear, validation, change signals, and resource-only Close.
   The [shared suite](internal/backend/backendtest/suite.go) checks the
   no-op and cleanup invariants for every backend.
4. [macOS convergence](internal/backend/darwin/converge.go) manages State keys
   and resolver files. [Windows convergence](internal/backend/windows/converge.go)
   manages NRPT placement and adapter settings, with
   [GUID-based recovery](internal/backend/windows/interface.go).
5. [Host locks](internal/hostlock) coordinate identity ownership and serialize
   attempts across processes. Manager Close joins the worker before its final
   cleanup, then calls backend Close to release resources.

Read tests alongside each implementation. [worker_test.go](worker_test.go)
uses a manual clock and [fake host](fakehost_test.go) for retries and goal
replacement. [identity_test.go](identity_test.go) and
[lifecycle_test.go](lifecycle_test.go) cover ownership and operation sequences.
The backends inject filesystem, subprocess, registry, adapter, and watcher
interfaces to exercise failures without changing the test host.

`internal/cmd/dnsconfigctl` exercises the public API and supplies the sentinel
DNS server and query helpers. `internal/cmd/smoketest` runs real OS scenarios,
including crashed predecessors and independent identities.

## Development checks

Use the Go version in [go.mod](go.mod). Format with `gofmt -s` or
`golangci-lint fmt`; lint checks the simplified form. gofmt rewrites `''` in
doc comments as a typographic quote, even inside backticks, so put
shell-quoting literals in an indented code block.

```sh
go build ./...
go test -race ./...
GOOS=darwin go vet ./...
GOOS=windows go vet ./...
GOOS=darwin golangci-lint run ./...
GOOS=windows golangci-lint run ./...
./scripts/check-readme-go.sh README.md
python3 scripts/check-markdown-links.py
```

[CI](.github/workflows/ci.yml) builds, vets, and runs native race tests on
macOS and Windows, and lints both trees. Cross-compilation does not execute
native API tests. Run live smoke rows only on disposable hosts; see the
[testing guide](docs/testing.md) for commands and coverage limits.

Use `testify/require` for preconditions and `testify/assert` for checks, with
`t.Run` for cases. Document every exported identifier with a sentence ending
in a period. Inject logging through `Options.Logger`; nil discards output.
Tests should establish caller-visible outcomes and recovery invariants.

## Documentation changes

Keep the README focused on evaluating and starting with the library.
The [package documentation](doc.go) and identifier godoc define API behavior;
[design notes](docs/design.md) explain surprising choices.

Verify claims against current code. Use concise ASCII prose and explain
constraints rather than narrating changes.

The split-DNS body in [example_test.go](example_test.go) is the canonical
quickstart. The README checker compares the excerpt and compiles the examples.
DNS-mutating examples have no `Output` comment, so tests compile them without
changing the host. The Markdown checker validates local links and heading
anchors; it does not fetch external URLs.
