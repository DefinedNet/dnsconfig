package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/DefinedNet/dnsconfig/internal/runner"
)

// Local executes a smoke row on the current machine.
// The platform executor owns DNS cleanup and privilege handling.
type Local struct {
	// Runner executes commands. Defaults to runner.ExecRunner.
	Runner runner.Runner
}

// NewLocal returns a Local driver using the production Runner.
func NewLocal() *Local {
	return &Local{Runner: runner.ExecRunner{}}
}

// run dispatches argv through Runner and preserves subprocess exit codes.
func (l *Local) run(ctx context.Context, argv []string) ExecResult {
	if len(argv) == 0 {
		return ExecResult{ExitCode: -1, Err: errors.New("local: empty argv")}
	}
	r := l.Runner
	if r == nil {
		r = runner.ExecRunner{}
	}
	name, args := argv[0], argv[1:]
	stdout, stderr, err := r.Run(ctx, name, args, nil)
	res := ExecResult{Stdout: stdout, Stderr: stderr, Err: err}
	switch err {
	case nil:
		res.ExitCode = 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	return res
}

// Exec runs argv as a local subprocess.
func (l *Local) Exec(ctx context.Context, argv ...string) ExecResult {
	return l.run(ctx, argv)
}

// CopyFile copies a file in-process, since Windows has no cp. Fixtures are
// executables, so the copy is created with mode 0755.
func (l *Local) CopyFile(src, dst string) ExecResult {
	data, err := os.ReadFile(localizeWindowsPath(src))
	if err != nil {
		return ExecResult{ExitCode: -1, Err: err}
	}
	if err := os.WriteFile(localizeWindowsPath(dst), data, 0o755); err != nil {
		return ExecResult{ExitCode: -1, Err: err}
	}
	return ExecResult{}
}

// localizeWindowsPath anchors driveless absolute paths to SystemDrive.
// The workspace may live on another drive, while Windows/Temp lives on the
// system drive. Already qualified and UNC paths retain their original root.
func localizeWindowsPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	p = filepath.FromSlash(p)
	if strings.HasPrefix(p, `\`) && !strings.HasPrefix(p, `\\`) {
		sysDrive := os.Getenv("SystemDrive")
		if sysDrive == "" {
			sysDrive = "C:"
		}
		p = sysDrive + p
	}
	return p
}
