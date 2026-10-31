// Pins deadcode, which the Dead code job in ci.yml builds from this module so
// its version and hashes come from here and Dependabot updates them (#1099).
module github.com/cfgaudit/cfgaudit/.github/tools/deadcode

go 1.26.0

tool golang.org/x/tools/cmd/deadcode

require (
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261009151841-97e8ea77aa2a // indirect
	golang.org/x/tools v0.52.0 // indirect
)
