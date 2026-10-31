// Pins pinact, which the pinact job in ci.yml builds from this module so its
// version and hashes come from here and Dependabot updates them (#1127).
module github.com/cfgaudit/cfgaudit/.github/tools/pinact

go 1.27.3

tool github.com/suzuki-shunsuke/pinact/v5/cmd/pinact

require (
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/expr-lang/expr v1.17.8 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/go-github/v93 v93.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lmittmann/tint v1.1.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/sourcegraph/go-diff v0.9.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/suzuki-shunsuke/cobra-util v0.0.5 // indirect
	github.com/suzuki-shunsuke/ghtkn-go-sdk v0.6.1 // indirect
	github.com/suzuki-shunsuke/go-error-with-exit-code v1.0.0 // indirect
	github.com/suzuki-shunsuke/go-github-device-flow v0.0.2 // indirect
	github.com/suzuki-shunsuke/go-revoke-github-access-token v0.0.2 // indirect
	github.com/suzuki-shunsuke/pinact/v5 v5.0.1 // indirect
	github.com/suzuki-shunsuke/slog-error v0.2.2 // indirect
	github.com/suzuki-shunsuke/slog-util v0.3.2 // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
