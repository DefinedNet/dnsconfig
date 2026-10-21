package main

import "context"

// Driver abstracts smoke-test side effects so row flows can use test doubles.
// Local executes on the current machine.
type Driver interface {
	// Exec runs argv and captures output and exit status.
	Exec(ctx context.Context, argv ...string) ExecResult

	// CopyFile copies a fixture to dst.
	CopyFile(src, dst string) ExecResult
}

var _ Driver = (*Local)(nil)
