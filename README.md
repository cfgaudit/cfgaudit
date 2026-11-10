# bench-data

Benchmark history of cfgaudit, written by `.github/workflows/bench-history.yml` on `main` (#1019). Do not edit by hand.

`bench.jsonl` holds one JSON object per push to `main`:

| Field | Meaning |
|---|---|
| `v` | format version, `1` |
| `sha`, `date` | the `main` commit and its commit date |
| `tag` | the latest release when the line was written (the ratio's reference) |
| `go`, `cpu` | Go version and runner CPU model; a CPU change explains a jump in time |
| `benchmarks` | per benchmark (name without the `Benchmark` prefix and CPU suffix): the median of each unit (`ns/op`, `B/op`, `allocs/op`, and custom units such as `init-ms/op`) over 10 runs, plus `ratio`, the median `ns/op` of this commit divided by that of `tag` measured in the same job, or `null` when `tag` predates the benchmarks |

Time depends on the runner; read it through `ratio`. `B/op` and `allocs/op` do not.

`ci-durations.jsonl` holds one JSON object per week, written by `.github/workflows/ci-durations.yml` (#1489): `schema`, `date`, `days`, `budget_minutes`, and in `workflows` and `jobs` the `name`, `runs`, `median`, `p90` and `max` in minutes.

`releases.jsonl` holds the scan time of every release, written by `.github/workflows/release-bench.yml` after each release and on request (#1619). Each run measures all releases in one job, taking turns, on the same generated input, so only records with the same `run` compare with each other. One JSON object per release and run:

| Field | Meaning |
|---|---|
| `schema` | format version, `1` |
| `kind` | `release` |
| `tag`, `commit`, `date` | the release, its commit and commit date |
| `rules` | number of rules (`cfgaudit list --format json`), `null` where the release lacks it |
| `input`, `input_sha256` | the generated input (a `benchcorpus` profile: `Release` since #1626, `Large` before) and a hash of its files |
| `run` | the workflow run id |
| `median_ms`, `runs_ms` | wall time of `cfgaudit <input>`: the median and every timed run, after one warm-up scan |
| `cpu`, `go` | runner CPU model and the Go version of the measuring job |
