# Accessibility

cfgaudit is a command-line scanner for AI coding agent configuration. Everyone, including people who use assistive technology, should be able to run it, read its findings, follow its documentation and contribute. This statement says what cfgaudit does for accessibility, how to report a barrier, and what we ask of contributors.

## The command-line tool

cfgaudit is not interactive: it reads files and prints a report. There is no terminal UI to navigate, so there is nothing to tab through or get trapped in.

- **Severity is text, never colour alone.** Every finding names its severity as a word (`error`, `warn`, `info`) next to the rule ID: `[error] CFG001` in the text format, the first column in the table. Where colour is on, it only emphasizes what the text already says.
- **Colour is optional, and off where it would get in the way.** cfgaudit honours `NO_COLOR` and the `--no-color` flag. It turns colour off by itself when the output is not a terminal, such as a pipe or a file. `FORCE_COLOR` or `CLICOLOR_FORCE` turn it back on, and `NO_COLOR` wins over both.
- **Machine-readable output for assistive tooling and automation.** Besides `text` and `table`, cfgaudit writes `json`, `sarif` and `codeclimate` (`--format`). Each carries every finding, so a screen reader, an editor or a script can present it in the way that suits the reader.
- **Plain-language findings.** A message states the problem and what to do, with a copyable `file:line:column` location.

A test (`cmd/cfgaudit/accessibility_test.go`) checks the first two points on every change.

## The website

The cfgaudit website ([cfgaudit.github.io](https://cfgaudit.github.io)) is checked on every change. Every page in its site checks must score 100 in Lighthouse's accessibility audit and pass axe, in the light and the dark theme. We work toward [WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/). That is a target, not a claim of verified conformance: an automated check cannot establish that a page is usable, so changes are also reviewed by hand.

## Reporting a barrier

If something about cfgaudit or its documentation stops you from using it, open an issue with the [accessibility template](https://github.com/cfgaudit/cfgaudit/issues/new?template=accessibility.yml). Tell us what you were doing, which tool and assistive technology you used, with versions, and what got in the way.

## What we ask of contributors

When you change how cfgaudit presents its output:

- keep the severity in the text, never as colour alone;
- keep `--no-color`, `NO_COLOR` and the non-terminal default working;
- keep the structured formats complete, so a reader who cannot use the text report has an equivalent.

For a website change, run the site checks and go through the page with a keyboard. Say in the pull request what you tested and what you could not.
