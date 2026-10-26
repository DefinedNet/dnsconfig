# Testing

Unit tests use OS doubles to exercise failures without changing system DNS.
Live smoke rows check resolution and cleanup on disposable hosts.

## Run the tests

From the repository root, with the Go version in [go.mod](../go.mod):

```sh
go build ./...
go test -race ./...
GOOS=darwin go vet ./...
GOOS=windows go vet ./...
./scripts/check-readme-go.sh README.md
```

See [development checks](../CONTRIBUTING.md#development-checks) for lint and
documentation checks. [CI](../.github/workflows/ci.yml) runs native tests on
both platforms; cross-vet does not execute Windows APIs on macOS.

## Run live smoke rows

Use the [macOS](../.github/workflows/smoke-macos.yml) and
[Windows](../.github/workflows/smoke-windows.yml) workflows on disposable CI
runners. They arrange privilege and platform fixtures. Dispatch them from
GitHub Actions or with the existing GitHub CLI:

```sh
gh workflow run smoke-macos.yml --ref <branch>
gh workflow run smoke-windows.yml --ref <branch>
```

The smoke harness changes the machine's DNS. On a disposable macOS host with
passwordless sudo, run `go run ./internal/cmd/smoketest -rows M1,M2`.
On a disposable Windows host, use the workflow's fixture wrapper from an
elevated PowerShell session:

```powershell
$env:RUNNER_TEMP = Join-Path $env:TEMP 'dnsconfig-smoke'
./.github/scripts/windows-library-smoke.ps1 -Row W1
```

The wrapper creates the controlled adapter and verifies its cleanup. W5 also
arranges LocalSystem execution. The Go harness accepts `-rows W1,W2` on Windows
when the required fixtures are supplied. Row prefixes must match the host;
unknown rows fail. Rows run sequentially because they share DNS. A failed row
runs its recovery steps unless the Go harness's `-keep-on-failure` flag is set.

## What is covered

| Layer | Checks |
| --- | --- |
| [Worker] | Backoff, pacing, signals, goal replacement, status; manual clock. |
| [Backend contract][suite] | Matching state causes no writes or side effects; failed side effects remain owed; backend Close releases resources only. |
| Backend and recovery tests | Injected read/write failures, partial cleanup, adapter recovery, and ownership boundaries. |
| Native tests | OS APIs and watcher lifecycles on their host platform. |
| [Go examples][examples] | Compilation; DNS-mutating examples do not run. |
| Smoke matrices | Apply, queries, replacement, cross-process cleanup; an idle Manager leaves installed DNS intact; catch-all rows remove a process's leftovers with `Recover` and find nothing on a second call. |

[Worker]: ../worker_test.go
[suite]: ../internal/backend/backendtest/suite.go
[examples]: ../example_test.go

Only live rows exercise native resolver selection and Group Policy notification
delivery. The [macOS matrix](../internal/cmd/smoketest/matrix_macos.go) and
[Windows matrix](../internal/cmd/smoketest/matrix_win.go) name the rows; the
[Windows library prelude][prelude] also checks adapter suffix replacement and
cleanup. The assertions live in the runners:

- [macOS runner][macos]: base-row search order and over-limit refusal, and M3
  signal-driven repair across a configd restart.
- [macOS pair runner][pair]: M7 shared search suffix.
- [Windows policy runner][policy]: W5 Group Policy NRPT beside a foreign
  rule, local copies after the container and the foreign rule leave, and the
  empty-container refusal.
- [Windows repair runner][repair]: W7 repair after a deleted rule and adapter
  value. It accepts periodic repair, so a pass does not prove registry
  notification delivery.

Live rows do not inject write failures or exercise a persistent competing
writer.

[prelude]: ../.github/scripts/windows-library-smoke.ps1
[macos]: ../internal/cmd/smoketest/runner_macos.go
[pair]: ../internal/cmd/smoketest/runner_pair_macos.go
[policy]: ../internal/cmd/smoketest/runner_win_gp.go
[repair]: ../internal/cmd/smoketest/runner_win_repair.go
