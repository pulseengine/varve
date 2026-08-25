#!/usr/bin/env python3
"""Assert the shape of the spec tools/build-deposit-spec.sh produced.

REQ-SYSTEST-002. `varve deposit` accepting the spec (which the gate also does)
proves it is well-formed TOML the schema accepts; it says nothing about whether
the RIGHT payloads were selected. That is what this checks, against the fixture
inventory in fixtures/deposit-layer/releases.tsv:

  * every declared tool is present for every platform its release ships, and
    for no platform it does not (loom has no aarch64-apple-darwin asset);
  * a repo in both lists contributes both a tool and a vsix;
  * a per-platform extension lands as one entry PER PLATFORM, each carrying
    its own platform and its own distinct asset — the property that lets a
    consumer resolve only their own;
  * a portable extension lands exactly once, with no platform at all;
  * `path` resolves relative to the spec file, as varve resolves it;
  * for payloads deposited as downloaded (raw binaries, .vsix), the recorded
    source sha256 is the sha256 of the staged bytes;
  * every payload names the mechanism that vouched for its bytes, and names the
    RIGHT one (REQ-INGEST-001 clause 2): the PulseEngine releases carry a
    cosign-signed sums file, the bytecodealliance one carries build provenance,
    and no payload may reach the spec with the question unanswered.

Usage: assert-deposit-spec.py <deposit-spec.toml>
"""

import hashlib
import pathlib
import sys
import tomllib

PLATFORMS = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
]
VSIX_TAG = {
    "aarch64-apple-darwin": "darwin-arm64",
    "x86_64-apple-darwin": "darwin-x64",
    "aarch64-unknown-linux-gnu": "linux-arm64",
    "x86_64-unknown-linux-gnu": "linux-x64",
}
# bytecodealliance's short platform tags, recorded from the live v1.257.1
# asset list on 2026-08-21 — not Rust target triples.
UPSTREAM_TAG = {
    "aarch64-apple-darwin": "aarch64-macos",
    "x86_64-apple-darwin": "x86_64-macos",
    "aarch64-unknown-linux-gnu": "aarch64-linux",
    "x86_64-unknown-linux-gnu": "x86_64-linux",
}
WSC_ASSET = {
    "aarch64-apple-darwin": "wsc-macos-aarch64",
    "x86_64-apple-darwin": "wsc-macos-x86_64",
    "aarch64-unknown-linux-gnu": "wsc-linux-aarch64",
    "x86_64-unknown-linux-gnu": "wsc-linux-x86_64",
}

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        failures.append(msg)


def main() -> int:
    spec_path = pathlib.Path(sys.argv[1]).resolve()
    spec_dir = spec_path.parent
    with spec_path.open("rb") as fh:
        spec = tomllib.load(fh)

    check(spec["channel"] == "rolling", f"channel is {spec['channel']!r}, expected 'rolling'")
    check(isinstance(spec["counter"], int), "counter must be a TOML integer, not a string")

    tools = spec.get("tool", [])
    by_name: dict[str, list[dict]] = {}
    for t in tools:
        by_name.setdefault(t["name"], []).append(t)

    # No (name, version, platform) may repeat: `varve deposit` refuses it, and
    # the assembler must not build one in the first place.
    seen: set[tuple] = set()
    for t in tools:
        key = (t["name"], t["version"], t.get("platform"))
        check(key not in seen, f"duplicate entry for {key}")
        seen.add(key)

    # Every path resolves, relative to the SPEC FILE's directory.
    for t in tools:
        p = spec_dir / t["path"]
        check(p.is_file(), f"{t['name']}: path {t['path']} does not resolve to a file next to the spec")

    # ── tools: one entry per platform the release actually ships ────────────
    def expect_tool(name: str, version: str, repo: str, release: str,
                    asset_of, platforms: list[str], proof: str = "cosign-sums") -> None:
        got = by_name.get(name, [])
        check(len(got) == len(platforms),
              f"{name}: {len(got)} entries, expected {len(platforms)} ({', '.join(platforms)})")
        for t in got:
            check(t.get("kind") is None, f"{name}: unexpected kind {t.get('kind')!r} on a tool entry")
            check(t["version"] == version, f"{name}: version {t['version']}, expected {version}")
            plat = t.get("platform")
            check(plat in platforms, f"{name}: entry for {plat}, which this release does not ship")
            src = t["source"]
            check(src["repo"] == repo, f"{name}/{plat}: source repo {src['repo']}, expected {repo}")
            check(src["release"] == release, f"{name}/{plat}: release {src['release']}, expected {release}")
            check(src["asset"] == asset_of(plat),
                  f"{name}/{plat}: asset {src['asset']}, expected {asset_of(plat)}")
            check(len(src["sha256"]) == 64, f"{name}/{plat}: sha256 {src['sha256']!r} is not a bare hex digest")
            check(src.get("proof") == proof,
                  f"{name}/{plat}: ingestion proof {src.get('proof')!r}, expected {proof!r}")

    expect_tool("rivet", "0.33.1", "pulseengine/rivet", "v0.33.1",
                lambda p: f"rivet-v0.33.1-{p}.tar.gz", PLATFORMS)
    expect_tool("spar", "0.36.0", "pulseengine/spar", "v0.36.0",
                lambda p: f"spar-v0.36.0-{p}.tar.gz", PLATFORMS)
    # The platform with no asset: a notice and an omission, not a failure.
    loom_platforms = [p for p in PLATFORMS if p != "aarch64-apple-darwin"]
    expect_tool("loom", "1.2.0", "pulseengine/loom", "v1.2.0",
                lambda p: f"loom-v1.2.0-{p}.tar.gz", loom_platforms)
    check(not any(t.get("platform") == "aarch64-apple-darwin" for t in by_name.get("loom", [])),
          "loom: an aarch64-apple-darwin entry exists for a release that ships no such asset")
    # kiln's CLI is `kilnd`: the entry is named for the BINARY, since that is
    # what `varve run` dispatches.
    expect_tool("kilnd", "0.4.4", "pulseengine/kiln", "v0.4.4",
                lambda p: f"kiln-v0.4.4-{p}.tar.gz", PLATFORMS)
    check("kiln" not in by_name, "a payload is named 'kiln'; the dispatched binary is 'kilnd'")
    expect_tool("wsc", "0.10.0", "pulseengine/sigil", "v0.10.0",
                lambda p: WSC_ASSET[p], PLATFORMS)
    # The second realm (REQ-INGEST-001): a foreign owner, upstream asset naming,
    # and BUILD PROVENANCE rather than a signed sums file. It is an ordinary
    # member of the layer — that is what "first-class" means.
    expect_tool("wasm-tools", "1.257.1", "bytecodealliance/wasm-tools", "v1.257.1",
                lambda p: f"wasm-tools-1.257.1-{UPSTREAM_TAG[p]}.tar.gz", PLATFORMS,
                proof="build-provenance")

    # ── vsix: one repo, two roles ───────────────────────────────────────────
    check(len(by_name.get("rivet", [])) == 4 and len(by_name.get("rivet-sdlc", [])) == 1,
          "rivet appears in both lists: expected 4 tool entries and 1 extension entry, got "
          f"{len(by_name.get('rivet', []))} and {len(by_name.get('rivet-sdlc', []))}")

    portable = by_name.get("rivet-sdlc", [])
    check(len(portable) == 1, f"rivet-sdlc: {len(portable)} entries, expected exactly 1 (portable)")
    for t in portable:
        check(t.get("kind") == "vsix", f"rivet-sdlc: kind {t.get('kind')!r}, expected 'vsix'")
        check("platform" not in t,
              f"rivet-sdlc: carries platform {t.get('platform')!r}; a portable package must carry none, "
              "or consumers on every other platform would not resolve it")
        check(t["source"]["asset"] == "rivet-sdlc-0.33.1.vsix",
              f"rivet-sdlc: asset {t['source']['asset']}")

    # Per-platform: one package each, each with its own platform and asset.
    perplat = by_name.get("spar-aadl", [])
    check(len(perplat) == len(PLATFORMS),
          f"spar-aadl: {len(perplat)} entries, expected one per platform ({len(PLATFORMS)})")
    got_platforms = sorted(t.get("platform") for t in perplat)
    check(got_platforms == sorted(PLATFORMS),
          f"spar-aadl: platforms {got_platforms}, expected {sorted(PLATFORMS)}")
    assets = [t["source"]["asset"] for t in perplat]
    check(len(set(assets)) == len(assets),
          f"spar-aadl: two platforms share one asset {assets} — a consumer would get another "
          "platform's package")
    for t in perplat:
        plat = t.get("platform")
        check(t.get("kind") == "vsix", f"spar-aadl/{plat}: kind {t.get('kind')!r}, expected 'vsix'")
        want = f"spar-aadl-{VSIX_TAG[plat]}-0.36.0.vsix"
        check(t["source"]["asset"] == want, f"spar-aadl/{plat}: asset {t['source']['asset']}, expected {want}")

    # ── payloads deposited AS DOWNLOADED must hash to their recorded sum ────
    # Only true where the payload is the asset (raw binaries, .vsix); a tarball
    # tool's sum is of the archive, not of the binary extracted from it.
    for t in tools:
        if t["name"] != "wsc" and t.get("kind") != "vsix":
            continue
        digest = hashlib.sha256((spec_dir / t["path"]).read_bytes()).hexdigest()
        check(digest == t["source"]["sha256"],
              f"{t['name']}/{t.get('platform')}: staged bytes hash to {digest} but the spec records "
              f"{t['source']['sha256']} — the spec would sign a sum for bytes it is not depositing")

    # ── nothing reaches the spec with its ingestion unaccounted for ─────────
    # The per-tool checks above name the mechanism they expect; this is the
    # blanket one, so a payload added later cannot slip in with the question
    # unanswered. Clause 3's shape at the spec level: silence is not an option.
    for t in tools:
        src = t.get("source")
        check(src is not None, f"{t['name']}: no [tool.source] at all")
        if src is None:
            continue
        check(src.get("proof") in ("cosign-sums", "build-provenance", "unverified"),
              f"{t['name']}/{t.get('platform')}: proof {src.get('proof')!r} is not a mechanism "
              "varve knows — every payload must say what vouched for its bytes")
        check(bool(src.get("proof-asserts")),
              f"{t['name']}/{t.get('platform')}: the mechanism is named but not what it asserted")
        if src.get("proof") == "unverified":
            check("proof-signer" not in src,
                  f"{t['name']}: nothing vouched for it, yet a signer is named")
        else:
            check(bool(src.get("proof-signer")),
                  f"{t['name']}/{t.get('platform')}: {src.get('proof')} names no signer")

    # A cosign-signed payload and an attested one must be TELLABLE APART from
    # the record alone — the point of clause 2. If every entry said the same
    # thing the checks above would still pass and the distinction would be
    # worthless.
    mechanisms = {t["source"].get("proof") for t in tools if t.get("source")}
    check(mechanisms == {"cosign-sums", "build-provenance"},
          f"this layer should mix both accepted mechanisms, got {sorted(m or '<none>' for m in mechanisms)}")

    total = 4 + 4 + 3 + 4 + 4 + 1 + 4 + 4
    check(len(tools) == total, f"{len(tools)} payloads in the spec, expected {total}")

    if failures:
        print(f"spec assertions FAILED ({len(failures)}):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"   spec assertions OK ({len(tools)} payloads, {len(by_name)} names)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
