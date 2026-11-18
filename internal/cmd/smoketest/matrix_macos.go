package main

// macosMatrix covers catch-all and split DNS on macOS 15 and 26.
// M5 also checks State-key repair across a configd restart and the
// notification child's delivery after it; M7 checks two application
// identities. Runner labels select CI hosts; the
// harness always runs on the current machine.
func macosMatrix() []Row {
	return []Row{
		{
			ID:   "M1",
			Name: "macOS 15 Sequoia (catch-all)",
		},
		{
			ID:           "M2",
			Name:         "macOS 15 Sequoia (split DNS + reverse zone)",
			Split:        true,
			ReverseSplit: true,
		},
		{
			ID:   "M5",
			Name: "macOS 26 Tahoe (catch-all)",
		},
		{
			ID:           "M6",
			Name:         "macOS 26 Tahoe (split DNS + reverse zone)",
			Split:        true,
			ReverseSplit: true,
		},
		{
			ID:    "M7",
			Name:  "macOS (two identities side by side)",
			Split: true,
			Pair:  true,
		},
	}
}
