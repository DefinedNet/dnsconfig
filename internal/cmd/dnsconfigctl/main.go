// Command dnsconfigctl is test scaffolding that exercises the dnsconfig
// library for the smoke-test harness and diagnostic probe scripts. It has no
// stable CLI surface.
//
// Usage:
//
//	dnsconfigctl [global flags] <subcommand> [subcommand flags] [args]
//
// Subcommands are listed in allCommands.
//
// Exit codes:
//
//	0   success
//	1   operation failed
//	2   usage error or backend doesn't support the requested operation
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/DefinedNet/dnsconfig"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// progName prefixes error messages.
const progName = "dnsconfigctl"

// defaultIdentity is the application identity used when -identity is absent.
const defaultIdentity = "dnsconfigctl"

// globalFlags holds the values parsed from the program-global flag set,
// shared by every subcommand.
type globalFlags struct {
	verbose  bool
	iface    string
	identity string
	backend  string
	logger   *slog.Logger
	stdout   io.Writer
	stderr   io.Writer
}

// parseGlobal consumes the leading global flags from args, returning the
// parsed globalFlags and the remaining args (subcommand + its args).
func parseGlobal(args []string, stdout, stderr io.Writer) (*globalFlags, []string, error) {
	g := &globalFlags{stdout: stdout, stderr: stderr}
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&g.verbose, "v", false, "enable debug logging to stderr")
	fs.BoolVar(&g.verbose, "verbose", false, "enable debug logging to stderr")
	fs.StringVar(&g.iface, "interface", "", "interface name passed to Manager")
	fs.StringVar(&g.identity, "identity", "", "application identity passed to Manager")
	fs.StringVar(&g.backend, "backend", "", "force a specific backend")
	err := fs.Parse(args)
	return g, fs.Args(), err
}

// resolveLogger constructs the slog.Logger the library should use. With -v,
// debug-level text output goes to stderr; without -v, a discard logger keeps
// the library's own log lines out of the user's terminal.
func (g *globalFlags) resolveLogger() *slog.Logger {
	if g.logger != nil {
		return g.logger
	}
	if g.verbose {
		h := slog.NewTextHandler(g.stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
		g.logger = slog.New(h)
	} else {
		g.logger = slog.New(slog.DiscardHandler)
	}
	return g.logger
}

// options builds library Options from the global flags.
func (g *globalFlags) options() (dnsconfig.Options, error) {
	identity := g.identity
	if identity == "" {
		// One fixed default keeps every smoke-harness process, including the
		// cross-process reset, on the same identity.
		identity = defaultIdentity
	}
	opts := dnsconfig.Options{
		Identity:      identity,
		Logger:        g.resolveLogger(),
		InterfaceName: g.iface,
	}
	if g.backend != "" {
		bk, ok := parseBackendKind(g.backend)
		if !ok {
			return opts, fmt.Errorf("unknown backend %q", g.backend)
		}
		opts.ForceBackend = bk
	}
	return opts, nil
}

// parseBackendKind maps the -backend flag to a dnsconfig.BackendKind. It is
// case-sensitive and accepts "auto" for the zero value; the set of names is
// BackendKind.IsValid's, so there is no second list to keep current.
func parseBackendKind(s string) (dnsconfig.BackendKind, bool) {
	if s == "" || s == "auto" {
		return dnsconfig.BackendAuto, true
	}
	k := dnsconfig.BackendKind(s)
	return k, k.IsValid()
}

// allCommands maps each subcommand name to its handler.
var allCommands = map[string]func(g *globalFlags, args []string) int{
	"detect": runDetect,
	"set":    runSet,
	"reset":  runReset,
	// The harness uses serve and probe-dns to start and check its sentinel.
	"serve":     runServe,
	"probe-dns": runProbeDNS,
	"lookup":    runLookup,
	// watch keeps a Manager alive to observe repair and teardown.
	"watch": runWatch,
}

// dispatch routes a parsed (globalFlags, args) tuple to the matching
// subcommand. Returns the subcommand's exit code, or exitUsage when the
// subcommand name is unknown.
func dispatch(g *globalFlags, args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(g.stderr, "%s: subcommand required\n", progName)
		return exitUsage
	}
	run, ok := allCommands[args[0]]
	if !ok {
		fmt.Fprintf(g.stderr, "%s: unknown subcommand %q\n", progName, args[0])
		return exitUsage
	}
	return run(g, args[1:])
}

// run is the testable entry point: it parses, dispatches, and returns an
// exit code. main.main calls run and forwards the code to os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	g, rest, err := parseGlobal(args, stdout, stderr)
	if err != nil {
		// The flag package has already reported the error.
		return exitUsage
	}
	return dispatch(g, rest)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// newSubFlagSet builds a FlagSet for a subcommand that reports parse errors
// to stderr instead of exiting.
func newSubFlagSet(sub string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}
