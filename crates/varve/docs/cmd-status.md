# varve status [--from-file <env>]

Reports the support window, yank state, and known problems for the pinned layer's line, from the newest verified line-status document (cached at install, or ingested with --from-file).

It also lists the active shim passthroughs (REQ-PASSTHROUGH-001): the tools your user-level configuration lets a shim run from PATH, the binary each would run, and any problem that keeps the configuration from taking effect. With no such configuration it prints nothing extra; `--json` always carries an `ambient_tools` object (`allowed`, `source`, `problem`, `active`). See `varve docs shim`.

For a MIXED toolchain — a pin with `[toolchain.override.<tool>]` (REQ-OVERRIDE-001) — the first line reads `MIXED toolchain <layer>+mixed: …` and each override is listed with its layer and digest; the line-status shown is the pinned layer's and does not cover the override layers. **Limit in v0.48.0:** a yank or end of support of an override layer's line is not reported, and `status` exits on the pinned layer's verdict alone, so a yanked override layer still exits 0 (varve#381). `--json` always carries `state` (`pinned` or `mixed`), `identity` (`<layer>` or `<layer>+mixed`) and `overrides` (`tool`, `layer`, `digest`).
