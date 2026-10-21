package main

// windowsMatrix returns the smoke-test matrix for the Windows rows, which the
// harness runs directly on GitHub-hosted Windows runners.
//
// Rows W1-W2 cover Windows Server 2025 (amd64); rows W3-W4 cover Windows 11 on
// GitHub's windows-11-arm runners -- the only client-SKU Windows runner
// offered, so that coverage is arm64. For each OS the first row exercises the
// catch-all NRPT path (namespace "." plus the NCSI exemption) and the second
// exercises split DNS via a per-suffix rule. Row W5 is the Group Policy NRPT
// row: it runs on Server 2025 and, unlike rows W1-W4, drives dnsconfigctl as
// LocalSystem so the GenerateGPNotification path actually executes. Row W6
// runs two application identities side by side on Server 2025, each on its
// own owned adapter; see runner_pair.go for what it proves. Row W7 deletes a
// live Manager's NRPT rule and adapter suffix on Server 2025 and requires the
// worker to restore both; see runner_win_repair.go. The workflow's
// runs-on selects the machine. Every row must detect "windows".
//
// The file is deliberately named matrix_win.go rather than
// matrix_windows.go: a *_windows.go suffix would attach an implicit
// //go:build windows constraint, and the smoke harness itself is built and
// tested on both macOS and Windows.
func windowsMatrix() []Row {
	return []Row{
		{
			ID:   "W1",
			Name: "Windows Server 2025 (catch-all NRPT)",
		},
		{
			ID:           "W2",
			Name:         "Windows Server 2025 (split DNS NRPT + reverse zone)",
			Split:        true,
			ReverseSplit: true,
		},
		{
			ID:   "W3",
			Name: "Windows 11 arm64 (catch-all NRPT)",
		},
		{
			ID:           "W4",
			Name:         "Windows 11 arm64 (split DNS NRPT + reverse zone)",
			Split:        true,
			ReverseSplit: true,
		},
		{
			ID:          "W5",
			Name:        "Windows Server 2025 (Group Policy NRPT, as LocalSystem)",
			Split:       true,
			GroupPolicy: true,
		},
		{
			ID:    "W6",
			Name:  "Windows Server 2025 (two identities side by side)",
			Split: true,
			Pair:  true,
		},
		{
			ID:     "W7",
			Name:   "Windows Server 2025 (live Manager repairs deleted NRPT rule and adapter suffix)",
			Split:  true,
			Repair: true,
		},
	}
}
