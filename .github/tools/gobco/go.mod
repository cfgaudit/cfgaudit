// Pins gobco, which the Branch coverage job in ci.yml builds from this module
// so its version and hashes come from here and Dependabot updates them (#756).
module github.com/cfgaudit/cfgaudit/.github/tools/gobco

go 1.24

tool github.com/rillig/gobco

require github.com/rillig/gobco v1.3.4 // indirect
