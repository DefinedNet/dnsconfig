#!/usr/bin/env bash
# Keep the README excerpt identical to the compiled godoc example.
set -euo pipefail

readme="${1:-README.md}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

awk '
    /^func ExampleManager_Set_splitDNS\(\) \{$/ { copying = 1; next }
    copying && /^}$/ { exit }
    copying { sub(/^\t/, ""); print }
' example_test.go > "$scratch/example.go"

awk '
    /^```go$/ { copying = 1; next }
    copying && /^```$/ { exit }
    copying { print }
' "$readme" > "$scratch/readme.go"

if [ ! -s "$scratch/example.go" ]; then
    echo "check-readme-go: split DNS example not found" >&2
    exit 1
fi
diff -u "$scratch/example.go" "$scratch/readme.go"
# Examples without Output comments compile but never change the test host's DNS.
go test -run '^$' .
echo "check-readme-go: README matches the compiled split DNS example"
