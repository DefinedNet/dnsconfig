package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMatrixInvariants guards the row tables against edits the executors
// cannot survive: -rows selects by ID, the reverse-zone check needs split
// routing, and a catch-all Group Policy rule would blackhole the runner's DNS.
func TestMatrixInvariants(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			_, rows := matrixFor(goos)
			seen := map[string]bool{}
			for _, row := range rows {
				assert.False(t, seen[row.ID], "duplicate row ID %s", row.ID)
				seen[row.ID] = true
				if row.ReverseSplit {
					assert.True(t, row.Split, "%s: ReverseSplit requires Split", row.ID)
				}
				if row.GroupPolicy {
					assert.True(t, row.Split, "%s: Group Policy row must be split", row.ID)
				}
			}
		})
	}
}
