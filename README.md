# dnsconfig

A Go library for configuring system DNS on macOS and Windows. It routes
queries to your nameservers through OS settings; your application supplies
the resolver and keeps it reachable. dnsconfig does not resolve or forward
queries itself.

[API reference](https://pkg.go.dev/github.com/DefinedNet/dnsconfig) |
[Examples](example_test.go) | [Design notes](docs/design.md) |
[FAQ](docs/faq.md) | [Contributing](CONTRIBUTING.md)

```sh
go get github.com/DefinedNet/dnsconfig
```

Requires Go 1.26 or newer. The public API may change before v1.0.

| Platform | Configuration mechanism |
| --- | --- |
| macOS | Synthetic SCDynamicStore keys and owned `/etc/resolver/` files. |
| Windows | NRPT rules and DNS settings on a caller-controlled adapter. |

Both support split DNS. Unsupported platforms refuse `Set` unless you
explicitly select `BackendNoop`.

## Quickstart: split DNS

Send `corp.example` and its subdomains to your resolver, leaving unrelated
names with the host's DNS. `SearchDomains` adds short-name expansion; each
search domain must equal or sit below a match domain in a split configuration.

Replace `192.0.2.53` with an already-running resolver. On Windows, replace
`myvpn0` with an existing adapter whose DNS settings you exclusively control;
macOS ignores the adapter name. This excerpt matches the
[complete Go example](example_test.go).

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()

m, err := dnsconfig.New(ctx, dnsconfig.Options{
	Identity:        "myapp",
	Logger:          slog.New(slog.NewTextHandler(os.Stderr, nil)),
	InterfaceName:   "myvpn0",
	ShutdownTimeout: 10 * time.Second,
})
if err != nil {
	log.Print(err)
	return
}
defer func() {
	if err := m.Close(); err != nil {
		log.Printf("DNS cleanup incomplete; recover with Clear under this identity: %v", err)
	}
}()

cfg := dnsconfig.Config{
	Nameservers:   []netip.Addr{netip.MustParseAddr("192.0.2.53")},
	MatchDomains:  []string{"corp.example"},
	SearchDomains: []string{"corp.example"},
}
// Set records the goal; the Manager applies, retries, and repairs it in
// the background. Status reports progress.
if err := m.Set(cfg); err != nil {
	log.Print(err)
	return
}

// Keep the resolver and its network path available through DNS cleanup.
<-ctx.Done()
```

## Applying and cleaning up

`New` starts a worker without changing DNS. `Set` records a complete
configuration, then returns. The worker applies it, retries host failures, and
repairs drift. Poll `Status`: `Converged` describes the latest installation
check, and `LastError` reports failures. It does not test application queries.

- Choose a stable `Identity` across restarts and distinct identities for
  independent instances. Exact domain or catch-all conflicts with another
  identity are refused before writes and retried. Unequal priority is not
  supported.
- `Set` replaces its goal without merging or reordering nameservers. A zero
  `Config` is invalid. Use `Clear` to remove this identity's settings and wait
  for `GoalClear` and `Converged` before treating cleanup as complete. The
  error `Close` returns reports Close as a whole. After `Close`, `Converged`
  is false for a Set goal and reports whether the cleanup succeeded for a
  Clear goal.
- Failed attempts do not roll back, so an error can accompany partial writes.
- Call `Close` during shutdown. If cleanup fails, recover with a fresh
  Manager's `Clear` under the same identity. `ShutdownTimeout` sets the
  cancellation deadline for final cleanup, including the host-lock wait;
  synchronous Windows API calls can exceed it. It does not bound all of
  `Close`; zero selects `DefaultShutdownTimeout`. See the
  [lifecycle examples](example_test.go).

## Limits

- **Privileges:** root is required on macOS. Windows consumers are expected to
  run as LocalSystem. Elevated Administrator operation falls back to a policy
  refresh that can leave removed rules effective after successful cleanup, so
  stopping the resolver can break DNS. See
  [Windows execution requirements](docs/design.md#direct-policy-notification-requires-localsystem).
- **Roaming and captive portals:** prefer split DNS. A catch-all needs a
  resolver that can answer every name and consumer-managed recovery when it
  becomes unreachable. dnsconfig does not discover upstreams or detect portal
  sign-in; on Windows, a catch-all exempts the default connectivity probe hosts
  so Windows can still detect a portal. See [catch-all recovery](docs/design.md#a-catch-all-needs-your-resolver-and-recovery-policy).
- **Windows adapter ownership:** the caller provides and controls the adapter.
  Cleanup clears its DNS settings without restoring older values. Global and
  policy search lists remain unchanged and may suppress adapter suffixes;
  short names can also depend on adapter preference.
- **Windows Group Policy:** foreign policy can require using the policy NRPT
  store; rules then also keep a local copy that takes over when that policy
  leaves. Applying while a policy container exists requires a live policy
  watcher. Windows activates and removes policy rules on its own schedule, and
  valid rules remain installed while activation is uncertain. See
  [Windows behavior](docs/design.md#windows-chooses-the-nrpt-store-from-foreign-policy).
- **Application resolvers:** private resolvers and encrypted-DNS policy can
  bypass these settings.

See the [documentation index](docs/README.md) for integration and testing guides.

## License

MIT. See [LICENSE](LICENSE).
