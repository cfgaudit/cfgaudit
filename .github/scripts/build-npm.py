# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
"""Pack the release binaries into npm packages (#1084).

    build-npm.py VERSION DIST OUT

Reads cfgaudit_VERSION_<os>_<arch>.tar.gz / .zip from DIST, which npm.yml has
already checked against checksums.txt and the build provenance, and writes to
OUT one package tarball per platform (@cfgaudit/<os>-<cpu>, holding only the
binary) and the main package cfgaudit. The main package lists the platform
packages as optionalDependencies, so npm installs only the one whose os and
cpu match, and its bin is a small launcher that runs that binary. There is no
install script and nothing is downloaded at install time, so it also works
with --ignore-scripts. The same archives always give the same tarballs.
"""
import gzip
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

# Release archive platform -> npm os and cpu (process.platform, process.arch).
PLATFORMS = {
    "linux_amd64": ("linux", "x64"),
    "linux_arm64": ("linux", "arm64"),
    "darwin_amd64": ("darwin", "x64"),
    "darwin_arm64": ("darwin", "arm64"),
    "windows_amd64": ("win32", "x64"),
    "windows_arm64": ("win32", "arm64"),
}

REPOSITORY = {"type": "git", "url": "git+https://github.com/cfgaudit/cfgaudit.git"}
HOMEPAGE = "https://cfgaudit.github.io"
DESCRIPTION = "Security auditor for AI-agent configuration files"

README = """\
# cfgaudit

Security auditor for AI-agent configuration files. cfgaudit reads the
committed configuration of Claude Code, Cursor, Codex, Gemini CLI, Copilot,
OpenCode and other coding agents (settings, MCP servers, hooks, skills,
instruction files) and reports what gives the agent more access than it
needs or runs code on whoever opens the repository. Findings map to the OWASP
GenAI LLM Top 10. It runs offline and only reads files.

```sh
npx cfgaudit@{version} .
npm install --save-dev --save-exact cfgaudit@{version}
```

Pin the version: cfgaudit itself reports an unpinned `npx` package in an MCP
server (CFG010).

This package runs the prebuilt binary of the GitHub release with the same
version, installed through the matching `@cfgaudit/<os>-<cpu>` package; the
archive it was taken from carries build provenance from the release workflow.
Documentation, rules and other install methods:
https://github.com/cfgaudit/cfgaudit
"""

PLATFORM_README = """\
# {name}

The prebuilt cfgaudit {version} binary for {os}/{cpu}. Install
[cfgaudit](https://www.npmjs.com/package/cfgaudit) instead; it pulls in this
package on matching systems.
"""

LAUNCHER = """\
#!/usr/bin/env node
// Copyright the cfgaudit contributors
// SPDX-License-Identifier: Apache-2.0
//
// Runs the cfgaudit binary from the @cfgaudit/<os>-<cpu> package npm installed
// for this system (#1084). Arguments, stdio and the exit code pass through.
"use strict";

const { spawnSync } = require("node:child_process");

const packages = {PACKAGES};
const key = `${process.platform} ${process.arch}`;
const pkg = packages[key];
if (!pkg) {
  console.error(`cfgaudit: no prebuilt binary for ${key}; see https://github.com/cfgaudit/cfgaudit#install`);
  process.exit(2);
}
const exe = process.platform === "win32" ? "cfgaudit.exe" : "cfgaudit";
let bin;
try {
  bin = require.resolve(`${pkg}/bin/${exe}`);
} catch {
  console.error(`cfgaudit: ${pkg} is not installed. npm installs it as an optional dependency of cfgaudit; reinstall without --omit=optional or --no-optional.`);
  process.exit(2);
}
const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(`cfgaudit: ${result.error.message}`);
  process.exit(2);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status ?? 2);
"""

# npm pack gives every entry this time, so a rebuild is byte-identical.
MTIME = 499162500  # 1985-10-26T08:15:00Z


def binary(archive):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            return z.read("cfgaudit.exe"), "cfgaudit.exe"
    with tarfile.open(archive) as t:
        member = t.extractfile("cfgaudit")
        if member is None:
            raise SystemExit(f"{archive}: cfgaudit is not a regular file")
        return member.read(), "cfgaudit"


def tarball(files, out):
    """Writes an npm package tarball: every entry under package/."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        for path, data, mode in sorted(files):
            info = tarfile.TarInfo("package/" + path)
            info.size, info.mode, info.mtime = len(data), mode, MTIME
            info.uname = info.gname = ""
            t.addfile(info, io.BytesIO(data))
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    out.write_bytes(buf.getvalue())


def manifest(data):
    return (json.dumps(data, indent=2) + "\n").encode()


def main():
    version, dist, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    license_text = None
    optional = {}
    packages = {}
    for platform, (os_, cpu) in PLATFORMS.items():
        ext = "zip" if platform.startswith("windows") else "tar.gz"
        archive = dist / f"cfgaudit_{version}_{platform}.{ext}"
        if license_text is None and ext == "tar.gz":
            with tarfile.open(archive) as t:
                license_text = t.extractfile("LICENSE").read()
        exe, exe_name = binary(archive)
        name = f"@cfgaudit/{os_}-{cpu}"
        optional[name] = version
        packages[f"{os_} {cpu}"] = name
        pkg = {
            "name": name,
            "version": version,
            "description": f"The cfgaudit binary for {os_}/{cpu}",
            "license": "Apache-2.0",
            "homepage": HOMEPAGE,
            "repository": REPOSITORY,
            "os": [os_],
            "cpu": [cpu],
            "preferUnplugged": True,
        }
        file = out / f"cfgaudit-{os_}-{cpu}-{version}.tgz"
        tarball([
            ("package.json", manifest(pkg), 0o644),
            ("README.md", PLATFORM_README.format(name=name, version=version, os=os_, cpu=cpu).encode(), 0o644),
            ("LICENSE", license_text, 0o644),
            (f"bin/{exe_name}", exe, 0o755),
        ], file)
        print(file.name)

    main_pkg = {
        "name": "cfgaudit",
        "version": version,
        "description": DESCRIPTION,
        "license": "Apache-2.0",
        "homepage": HOMEPAGE,
        "repository": REPOSITORY,
        "bugs": {"url": "https://github.com/cfgaudit/cfgaudit/issues"},
        "keywords": ["ai", "agents", "claude-code", "mcp", "security", "linter", "configuration"],
        "bin": {"cfgaudit": "bin/cfgaudit.js"},
        "engines": {"node": ">=18"},
        "optionalDependencies": optional,
    }
    launcher = LAUNCHER.replace("{PACKAGES}", json.dumps(packages, indent=2).replace("\n", "\n"))
    file = out / f"cfgaudit-{version}.tgz"
    tarball([
        ("package.json", manifest(main_pkg), 0o644),
        ("README.md", README.format(version=version).encode(), 0o644),
        ("LICENSE", license_text, 0o644),
        ("bin/cfgaudit.js", launcher.encode(), 0o755),
    ], file)
    print(file.name)


if __name__ == "__main__":
    main()
