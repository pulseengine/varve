# varve status [--from-file <env>]

Reports the support window, yank state, and known problems for the pinned layer's line, from the newest verified line-status document (cached at install, or ingested with --from-file).

It also lists the active shim passthroughs (REQ-PASSTHROUGH-001): the tools your user-level configuration lets a shim run from PATH, the binary each would run, and any problem that keeps the configuration from taking effect. With no such configuration it prints nothing extra; `--json` always carries an `ambient_tools` object (`allowed`, `source`, `problem`, `active`). See `varve docs shim`.
