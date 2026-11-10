# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0

"""Measure the scan time of release binaries on one input (#1619).

Usage: release-bench.py RELEASES INPUT INPUT_NAME OUT RUN_ID GO_VERSION [RUNS]

RELEASES is a tab-separated file with one release per line: tag, binary,
commit, date. INPUT_NAME says which generated tree INPUT is, such as
benchcorpus.Release, and goes into every record. Every binary scans INPUT once to warm up and then RUNS times
(default 7). The releases take turns, one scan each per round, so a runner
that slows down mid-job affects every release alike. One JSON record per
release goes to OUT; the format is described in the bench-data README.

A scan exits 0 or 1 (no findings or findings). Any other exit code, or a
binary that does not start, skips the release with a GitHub warning, so one
broken old release does not lose the others.
"""

import hashlib
import json
import os
import statistics
import subprocess
import sys
import threading
import time

TIMEOUT_SECONDS = 120


def warn(message):
    print(f"::warning::{message}", flush=True)


def input_digest(root):
    """sha256 over the sorted relative paths and contents of every file."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            digest.update(rel.encode() + b"\0")
            with open(path, "rb") as f:
                digest.update(f.read())
            digest.update(b"\0")
    return digest.hexdigest()


def rule_count(binary):
    """Length of `list --format json`, or None where the release lacks it."""
    try:
        out = subprocess.run(
            [binary, "list", "--format", "json"],
            capture_output=True, timeout=TIMEOUT_SECONDS, check=False,
        )
        rules = json.loads(out.stdout) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return len(rules) if isinstance(rules, list) else None


def scan_ms(binary, root):
    """Wall time of one scan in ms, or None when the scan did not finish.

    The wait blocks in waitpid. Popen.wait or subprocess.run with a timeout
    polls instead, sleeping up to 50 ms between polls, which rounded every
    time up to 14 ms plus a multiple of 50 (#1629). A timer kills a scan that
    runs past TIMEOUT_SECONDS.
    """
    start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            [binary, root], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    timer = threading.Timer(TIMEOUT_SECONDS, proc.kill)
    timer.start()
    try:
        code = proc.wait()
    finally:
        timer.cancel()
    elapsed = (time.perf_counter() - start) * 1000
    return round(elapsed, 1) if code in (0, 1) else None


def cpu_model():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def main(argv):
    if len(argv) not in (7, 8):
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    releases_file, root, input_name, out_file, run_id, go_version = argv[1:7]
    runs = int(argv[7]) if len(argv) == 8 else 7

    releases = []
    with open(releases_file, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                tag, binary, commit, date = line.rstrip("\n").split("\t")
                releases.append({"tag": tag, "binary": binary, "commit": commit, "date": date})

    measured = []
    for rel in releases:
        if scan_ms(rel["binary"], root) is None:
            warn(f"{rel['tag']}: the scan did not finish; skipped")
            continue
        rel["times"] = []
        measured.append(rel)
    for _ in range(runs):
        for rel in measured:
            ms = scan_ms(rel["binary"], root)
            if ms is None:
                rel["failed"] = True
            else:
                rel["times"].append(ms)

    digest, cpu = input_digest(root), cpu_model()
    written = 0
    with open(out_file, "w", encoding="utf-8") as out:
        for rel in measured:
            if rel.get("failed"):
                warn(f"{rel['tag']}: a timed scan did not finish; skipped")
                continue
            record = {
                "schema": 1,
                "kind": "release",
                "tag": rel["tag"],
                "commit": rel["commit"],
                "date": rel["date"],
                "rules": rule_count(rel["binary"]),
                "input": input_name,
                "input_sha256": digest,
                "run": int(run_id),
                "median_ms": round(statistics.median(rel["times"]), 1),
                "runs_ms": rel["times"],
                "cpu": cpu,
                "go": go_version,
            }
            out.write(json.dumps(record, separators=(",", ":")) + "\n")
            written += 1
    print(f"measured {written} of {len(releases)} releases")
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
