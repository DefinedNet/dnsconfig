package main

// Row describes one macOS or Windows smoke scenario.
type Row struct {
	// ID is the matrix prefix joined to the row number, e.g. "M3". It is what
	// -rows accepts and what log lines print.
	ID string
	// Name is the description printed in logs.
	Name string
	// Split tests per-suffix routing and an unrelated upstream control query.
	Split bool
	// ReverseSplit also routes and verifies the sentinel's reverse zone.
	ReverseSplit bool
	// GroupPolicy selects the Windows LocalSystem NRPT scenario.
	GroupPolicy bool
	// Pair runs two application identities side by side; see runner_pair.go.
	Pair bool
	// Repair holds a live Manager while the harness deletes its Windows
	// artifacts; see runner_win_repair.go.
	Repair bool
}

const (
	prefixMacos   = "M"
	prefixWindows = "W"
)

// matrixFor returns goos's row prefix and rows. Other platforms have no rows.
func matrixFor(goos string) (string, []Row) {
	switch goos {
	case "darwin":
		return prefixMacos, macosMatrix()
	case "windows":
		return prefixWindows, windowsMatrix()
	}
	return "", nil
}
