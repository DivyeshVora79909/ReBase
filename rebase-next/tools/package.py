#!/usr/bin/env python3
"""Build committed ReBase Next sources outside Git and package a native Linux bundle."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def command(*args, cwd=ROOT):
    return subprocess.run([str(arg) for arg in args], cwd=cwd, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="New directory for archive, checksums and build evidence")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/native-slice/build",
                        help="Reusable Cargo compilation cache; only archived sources are built")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("this bundle profile targets native Linux x86_64")
    if os.environ.get("CARGO_BUILD_TARGET"):
        parser.error("unset CARGO_BUILD_TARGET for this native build")
    repository = Path(command("git", "rev-parse", "--show-toplevel").decode().strip())
    commit = command("git", "rev-parse", "HEAD").decode().strip()
    prefix = command("git", "rev-parse", "--show-prefix").decode().strip().rstrip("/")
    source_tree = command("git", "rev-parse", f"{commit}:{prefix}").decode().strip()
    epoch = int(command("git", "show", "-s", "--format=%ct", commit))
    archive = command("git", "archive", "--format=tar", source_tree, cwd=repository)
    target = args.target_dir.resolve()
    destination = args.out.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    rustc = command("rustc", "-Vv").decode().strip()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rebase-next-build-") as temporary:
        copied = Path(temporary) / "source"
        copied.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            if any(not (member.isfile() or member.isdir()) for member in source.getmembers()):
                raise RuntimeError("release sources must contain only regular files and directories")
            source.extractall(copied, filter="data")
        inside_git = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=copied,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if inside_git.returncode == 0:
            raise RuntimeError("isolated build directory is inside Git")
        source_hashes = {str(path.relative_to(copied)): digest(path)
                         for path in sorted(copied.rglob("*")) if path.is_file()}
        build = ["cargo", "build", "--locked", "--release", "--manifest-path", str(copied / "Cargo.toml"),
                 "--target-dir", str(target), "--bin", "rebase-next"]
        print(f"Building committed source {commit} outside Git; log: {destination / 'build.log'}", flush=True)
        with (destination / "build.log").open("wb") as log:
            subprocess.run(build, cwd=copied, env=dict(os.environ, CARGO_INCREMENTAL="0"),
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        elapsed = round(time.monotonic() - started, 3)
        (copied / "bin").mkdir()
        binary = copied / "bin/rebase-next"
        shutil.copyfile(target / "release/rebase-next", binary)
        binary.chmod(0o755)
        version = tomllib.loads((copied / "Cargo.toml").read_text())["package"]["version"]
        models = {}
        for name in ("calculation", "equipment", "invoicing"):
            identity = json.loads(command(binary, "--model", name, "version", cwd=copied))
            catalog = json.loads(command(binary, "--model", name, "model", "public", cwd=copied))
            if identity["version"] != version or identity["model"] != catalog["model"]:
                raise RuntimeError("compiled package/catalog identity differs")
            models[name] = {**identity, "codec": catalog["codec"], "limits": catalog["capabilities"]["limits"]}
        symbols = command("readelf", "--version-info", binary).decode()
        glibc = max(tuple(map(int, value.split("."))) for value in re.findall(r"GLIBC_([0-9.]+)", symbols))
        dynamic = command("readelf", "--dynamic", binary).decode()
        manifest = {
            "format": "rebase-deployment-bundle-1", "package_version": version,
            "source_commit": commit, "source_tree": source_tree, "source_timestamp": epoch,
            "source_files": source_hashes, "binary_sha256": digest(binary), "models": models,
            "build": {"rustc": rustc, "cargo": command("cargo", "--version").decode().strip(),
                      "profile": "release", "locked": True, "incremental": False, "outside_git": True},
            "platform": {"system": platform.system(), "machine": platform.machine(),
                         "kernel": platform.release(), "libc": list(platform.libc_ver()),
                         "minimum_glibc": ".".join(map(str, glibc)),
                         "shared_libraries": re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)},
            "tools_require": ["Python 3.11+", "OpenSSL for issuer keys and acceptance workflows"],
            "scope": "One embedded process, tenant and selected model per store; see docs/deployment.md",
        }
        write_json(copied / "BUNDLE.json", manifest)
        files = sorted(path for path in copied.rglob("*") if path.is_file())
        with (copied / "SHA256SUMS").open("w") as checksums:
            for path in files:
                name = str(path.relative_to(copied))
                if "\n" in name or "\\" in name:
                    raise RuntimeError("unsupported checksum filename")
                checksums.write(f"{digest(path)}  {name}\n")
        stem = f"rebase-next-{version}-linux-x86_64"
        bundle = destination / f"{stem}.tar.gz"

        def normalized(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.pax_headers = {}
            return info

        with bundle.open("xb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as packed:
                    packed.add(copied, arcname=stem, filter=normalized)
        checksum = digest(bundle)
        bundle.with_suffix(bundle.suffix + ".sha256").write_text(f"{checksum}  {bundle.name}\n")
        write_json(destination / "BUNDLE.json", manifest)
        report = {"status": "packaged; extracted workflow acceptance is separate", "source_commit": commit,
                  "source_tree": source_tree, "bundle": bundle.name, "bundle_sha256": checksum,
                  "bundle_bytes": bundle.stat().st_size, "binary_sha256": manifest["binary_sha256"],
                  "source_files": len(source_hashes), "checksummed_files": len(files),
                  "build": {"command": build, "outside_git": True, "elapsed_seconds": elapsed,
                            "log": "build.log", "source_directory_removed_after_packaging": True}}
        write_json(destination / "result.json", report)
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
