#!/usr/bin/env python3
"""Build a varve deposit spec from a real Cargo.lock (REQ-SYSTEST-001 clause 1).

Every `[[package]]` in the lockfile that came from the crates.io registry
becomes one `kind = "crate"` entry in the spec, its bytes taken from the local
cargo cache (`~/.cargo/registry/cache/<index>/name-version.crate` — populate it
with `cargo fetch`). The sha256 of each `.crate` file is checked against the
lockfile's `checksum` BEFORE it is offered for deposit: the layer must pin the
exact bytes the lock pins, or the downstream `cargo build --offline --locked`
oracle would be comparing varve against a different graph.

This is deliberately NOT a toy fixture generator. The scale guards at the
bottom fail the run if the lockfile stops being a realistic case (a real
dependency graph, several names at more than one version) — the exact
properties whose absence made varve#73 invisible to `cargo_offline.rs`.
"""

import argparse
import hashlib
import pathlib
import re
import sys


def parse_lock(path: pathlib.Path):
    """Registry packages from a Cargo.lock: (name, version, checksum).

    Cargo.lock is machine-generated with a stable field order (name, version,
    source?, checksum?, dependencies?), so a block-wise scan is reliable and
    keeps this runnable on any Python 3 (no tomllib requirement).
    """
    pkgs = []
    text = path.read_text(encoding="utf-8")
    for block in text.split("[[package]]")[1:]:
        fields = dict(re.findall(r'^(\w+) = "([^"]*)"$', block, re.M))
        source = fields.get("source", "")
        if not source.startswith("registry+"):
            continue  # path/git packages carry no registry bytes to deposit
        if "checksum" not in fields:
            raise SystemExit(
                f"error: {fields.get('name')}@{fields.get('version')} is a "
                "registry package without a checksum — refusing to deposit "
                "bytes the lockfile does not pin"
            )
        pkgs.append((fields["name"], fields["version"], fields["checksum"]))
    return pkgs


def find_crate(cache_dirs, name, version):
    fname = f"{name}-{version}.crate"
    for cache in cache_dirs:
        for candidate in sorted(cache.glob(f"*/{fname}")) + [cache / fname]:
            if candidate.is_file():
                return candidate
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", required=True, type=pathlib.Path)
    ap.add_argument(
        "--cache",
        required=True,
        type=pathlib.Path,
        action="append",
        help="cargo registry cache dir (the one holding index.crates.io-*/); repeatable",
    )
    ap.add_argument("--layer", required=True)
    ap.add_argument("--channel", default="rolling")
    ap.add_argument("--counter", type=int, default=1)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args()

    pkgs = parse_lock(args.lock)
    if not pkgs:
        raise SystemExit(f"error: no registry packages found in {args.lock}")

    lines = [
        f'layer = "{args.layer}"',
        f'channel = "{args.channel}"',
        f"counter = {args.counter}",
    ]
    missing, mismatched = [], []
    for name, version, checksum in pkgs:
        crate = find_crate(args.cache, name, version)
        if crate is None:
            missing.append(f"{name}-{version}.crate")
            continue
        digest = hashlib.sha256(crate.read_bytes()).hexdigest()
        if digest != checksum:
            mismatched.append(f"{name}-{version}: cache {digest} != lock {checksum}")
            continue
        # TOML strings: crates.io names/versions are ASCII [a-zA-Z0-9_-] and
        # [0-9a-zA-Z.+-], so plain quoting is safe; paths are absolute.
        lines += [
            "",
            "[[tool]]",
            f'name = "{name}"',
            f'version = "{version}"',
            f'path = "{crate.resolve()}"',
            'kind = "crate"',
        ]
    if missing:
        raise SystemExit(
            "error: %d .crate file(s) absent from the cache (run `cargo fetch` "
            "first): %s ..." % (len(missing), ", ".join(missing[:5]))
        )
    if mismatched:
        raise SystemExit(
            "error: cache bytes disagree with the lockfile:\n  " + "\n  ".join(mismatched)
        )

    # Scale guards: the whole point of this spec is that it is NOT a toy.
    names = {}
    for name, version, _ in pkgs:
        names.setdefault(name, set()).add(version)
    multi = {n: sorted(v) for n, v in names.items() if len(v) > 1}
    if len(pkgs) < 100 or len(multi) < 5:
        raise SystemExit(
            f"error: lockfile yields {len(pkgs)} registry packages with "
            f"{len(multi)} multi-version names — below the realistic-scale floor "
            "(>=100 packages, >=5 names at more than one version) this "
            "gate exists to enforce (REQ-SYSTEST-001)"
        )

    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        f"wrote {args.out}: {len(pkgs)} crate entries, "
        f"{len(multi)} names at more than one version: "
        + ", ".join(f"{n} ({len(v)})" for n, v in sorted(multi.items()))
    )


if __name__ == "__main__":
    sys.exit(main())
