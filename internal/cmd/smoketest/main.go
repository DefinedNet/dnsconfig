// Command smoketest runs macOS and Windows DNS smoke scenarios on the host.
// It builds dnsconfigctl and exercises detection, apply, routing, and cleanup.
// Rows use M<n> for macOS and W<n> for Windows; the host selects the matrix.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain is the testable entrypoint. It parses flags, builds the binary,
// runs the selected matrix rows, and returns the exit code main forwards to
// os.Exit.
func realMain(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("smoketest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rowsFlag := fs.String("rows", "", "comma-separated prefixed row ids to run, e.g. M1,M2 (default: all rows in the host matrix)")
	keepFlag := fs.Bool("keep-on-failure", false, "preserve DNS state when a row fails")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := func(format string, a ...any) {
		fmt.Fprintf(stdout, format+"\n", a...)
	}

	rows, err := parseRowsSelectionFor(runtime.GOOS, *rowsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "smoketest: -rows: %v\n", err)
		return 2
	}
	if len(rows) == 0 {
		fmt.Fprintf(stderr, "smoketest: no rows selected\n")
		return 2
	}

	binary := tempBinaryPath()
	defer func() { _ = os.Remove(binary) }()

	log("building dnsconfigctl for native %s/%s -> %s", runtime.GOOS, runtime.GOARCH, binary)
	if err := buildNativeBinary(binary); err != nil {
		fmt.Fprintf(stderr, "smoketest: build: %v\n", err)
		return 1
	}

	cfg := runConfig{
		Driver:        NewLocal(),
		Binary:        binary,
		KeepOnFailure: *keepFlag,
		Log:           log,
	}

	results := runRowsFor(context.Background(), runtime.GOOS, cfg, rows)
	return reportSummary(results, log)
}

// buildNativeBinary builds dnsconfigctl for the local runner with CGO disabled.
func buildNativeBinary(out string) error {
	return buildNativePkg(out, "./internal/cmd/dnsconfigctl")
}

// buildNativePkg builds pkg for the host with CGO disabled.
func buildNativePkg(out, pkg string) error {
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// parseRowsSelectionFor selects rows from goos's matrix. Empty input selects
// all rows. Explicit IDs must include the matrix prefix so a row from another
// platform cannot be selected accidentally.
func parseRowsSelectionFor(goos, raw string) ([]Row, error) {
	prefix, rows := matrixFor(goos)
	if rows == nil {
		return nil, errors.New("smoke tests require macOS or Windows")
	}
	if strings.TrimSpace(raw) == "" {
		return rows, nil
	}
	var out []Row
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := checkRowPrefix(p, prefix); err != nil {
			return nil, err
		}
		i := slices.IndexFunc(rows, func(r Row) bool { return strings.EqualFold(r.ID, p) })
		if i < 0 {
			return nil, fmt.Errorf("row %s: %w", p, errUnknownRow)
		}
		out = append(out, rows[i])
	}
	return out, nil
}

// checkRowPrefix requires tok's prefix to be want, the active matrix's tag. A
// prefix naming a different matrix is reported specifically, because that is
// the likely mistake: the -rows value was copied from a workflow for another
// platform.
func checkRowPrefix(tok, want string) error {
	got := strings.ToUpper(tok[:1])
	switch got {
	case prefixMacos, prefixWindows:
	default:
		return fmt.Errorf("invalid row %q: rows are prefixed by matrix - %s<n> for macOS, %s<n> for Windows",
			tok, prefixMacos, prefixWindows)
	}
	if got != want {
		return fmt.Errorf("row %q belongs to the %s matrix, but this run selects the %s matrix", tok, got, want)
	}
	return nil
}

// rowResult bundles the outcome of one row execution for the summary.
type rowResult struct {
	Row     Row
	Outcome rowOutcome
}

// runRowsFor executes the selected rows of goos's matrix and records their
// outcomes. Rows share the host's DNS configuration, so execution must be
// sequential.
func runRowsFor(ctx context.Context, goos string, cfg runConfig, rows []Row) []rowResult {
	exec := executeRowMacos
	if goos == "windows" {
		exec = executeRowWindows
	}
	results := make([]rowResult, len(rows))
	for i, row := range rows {
		results[i] = rowResult{Row: row, Outcome: exec(ctx, cfg, row)}
	}
	return results
}

// reportSummary prints the per-row pass/fail line followed by the
// aggregate totals, and returns the process exit code: 0 iff no rows failed.
func reportSummary(results []rowResult, log func(string, ...any)) int {
	var passed, failed int
	for _, r := range results {
		switch r.Outcome {
		case outcomePassed:
			passed++
		case outcomeFailed:
			failed++
		}
	}
	log("")
	log("=== summary ===")
	for _, r := range results {
		log("  row %s (%s): %s", r.Row.ID, r.Row.Name, r.Outcome)
	}
	log("PASSED: %d / FAILED: %d", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// errUnknownRow is returned by parseRowsSelectionFor when a row ID does not
// match any matrix entry. Exposed so tests can assert via errors.Is.
var errUnknownRow = errors.New("smoketest: unknown matrix row")
