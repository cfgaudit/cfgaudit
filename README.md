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
