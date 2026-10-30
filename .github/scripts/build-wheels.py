# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0
"""Pack the release binaries into platform wheels for PyPI (#1083).

    build-wheels.py VERSION DIST OUT

Reads cfgaudit_VERSION_<os>_<arch>.tar.gz / .zip from DIST, which pypi.yml has
already checked against checksums.txt and the build provenance, and writes one
wheel per platform to OUT. The binary goes under cfgaudit-VERSION.data/scripts/,
so pip, pipx and uv install it straight onto PATH: no Python wrapper, nothing
downloaded at install time. The same archives always give the same wheels.
"""
import base64
import hashlib
import io
import sys
import tarfile
import zipfile
from pathlib import Path

# The Go binaries are static (CGO_ENABLED=0), so one Linux build serves both
# glibc and musl. Go needs macOS 11 or later.
PLATFORMS = {
    "linux_amd64": ["manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64"],
    "linux_arm64": ["manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64"],
    "darwin_amd64": ["macosx_11_0_x86_64"],
    "darwin_arm64": ["macosx_11_0_arm64"],
    "windows_amd64": ["win_amd64"],
    "windows_arm64": ["win_arm64"],
}

DESCRIPTION = """\
# cfgaudit

Security auditor for AI-agent configuration files. cfgaudit reads the
committed configuration of Claude Code, Cursor, Codex, Gemini CLI, Copilot,
OpenCode and other coding agents (settings, MCP servers, hooks, skills,
instruction files) and reports what gives the agent more access than it
needs or runs code on whoever opens the repository. Findings map to the OWASP
GenAI LLM Top 10. It runs offline and only reads files.

```sh
pipx install cfgaudit      # or: uv tool install cfgaudit
uvx cfgaudit .
```

This package ships the prebuilt binary of the GitHub release with the same
version; the archive it was taken from carries build provenance from the
release workflow. Documentation, rules and other install methods:
https://github.com/cfgaudit/cfgaudit
"""

# Fixed timestamp for every entry, so a rebuild gives identical wheels.
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def binary(archive):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            return z.read("cfgaudit.exe"), "cfgaudit.exe"
    with tarfile.open(archive) as t:
        member = t.extractfile("cfgaudit")
        if member is None:
            raise SystemExit(f"{archive}: cfgaudit is not a regular file")
        return member.read(), "cfgaudit"


def record_hash(data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode()


def metadata(version):
    lines = [
        "Metadata-Version: 2.4",
        "Name: cfgaudit",
        f"Version: {version}",
        "Summary: Security auditor for AI-agent configuration files",
        "License-Expression: Apache-2.0",
        "License-File: LICENSE",
        "Project-URL: Homepage, https://cfgaudit.github.io",
        "Project-URL: Source, https://github.com/cfgaudit/cfgaudit",
        "Project-URL: Issues, https://github.com/cfgaudit/cfgaudit/issues",
        "Project-URL: Changelog, https://github.com/cfgaudit/cfgaudit/releases",
        "Keywords: ai,agents,claude-code,mcp,security,linter,configuration",
        "Classifier: Environment :: Console",
        "Classifier: Intended Audience :: Developers",
        "Classifier: Operating System :: OS Independent",
        "Classifier: Topic :: Security",
        "Classifier: Topic :: Software Development :: Quality Assurance",
        "Description-Content-Type: text/markdown",
    ]
    return ("\n".join(lines) + "\n\n" + DESCRIPTION).encode()


def wheel(version, platform, exe, exe_name, license_text, out):
    tags = PLATFORMS[platform]
    name = f"cfgaudit-{version}-py3-none-{'.'.join(tags)}.whl"
    dist_info = f"cfgaudit-{version}.dist-info"
    wheel_meta = "Wheel-Version: 1.0\nGenerator: cfgaudit build-wheels.py\nRoot-Is-Purelib: false\n"
    wheel_meta += "".join(f"Tag: py3-none-{t}\n" for t in tags)
    files = [
        (f"cfgaudit-{version}.data/scripts/{exe_name}", exe, 0o755),
        (f"{dist_info}/METADATA", metadata(version), 0o644),
        (f"{dist_info}/WHEEL", wheel_meta.encode(), 0o644),
        (f"{dist_info}/licenses/LICENSE", license_text, 0o644),
    ]
    record = "".join(f"{path},{record_hash(data)},{len(data)}\n" for path, data, _ in files)
    record += f"{dist_info}/RECORD,,\n"
    files.append((f"{dist_info}/RECORD", record.encode(), 0o644))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, data, mode in files:
            info = zipfile.ZipInfo(path, ZIP_TIME)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    (out / name).write_bytes(buf.getvalue())
    return name


def main():
    version, dist, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    license_text = None
    for platform in PLATFORMS:
        ext = "zip" if platform.startswith("windows") else "tar.gz"
        archive = dist / f"cfgaudit_{version}_{platform}.{ext}"
        if license_text is None and ext == "tar.gz":
            with tarfile.open(archive) as t:
                license_text = t.extractfile("LICENSE").read()
        exe, exe_name = binary(archive)
        print(wheel(version, platform, exe, exe_name, license_text, out))


if __name__ == "__main__":
    main()
