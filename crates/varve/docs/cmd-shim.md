# varve shim install

Installs PATH dispatchers that resolve the pin from the invocation's working directory and exec the right binary — switching projects is just cd.

A shim IS the varve binary, reached under another name: on unix, a symlink. Where only a copy is possible — Windows — `shim install` REFUSES rather than writing one, because a copy binds to the varve that existed when you ran it: `self-update` would replace the binary and leave every shim running the old verification and refusal logic, with nothing saying so. Use `varve run <tool>` there; it resolves the pin on every invocation and is never stale. Which mechanism should replace the copy is open on purpose (DD-031, varve#197). varve looks at the name it was invoked as and dispatches that tool. There is no shell script and no shell, so nothing on the dispatch path parses a string, and the dispatch costs one process instead of two. Arguments pass through as raw bytes, so a filename that is not valid UTF-8 reaches the tool unchanged.

A consequence worth knowing (rustup behaves the same way): the binary must be named `varve` to offer the CLI. A copy called `varve-0.19` or `myvarve` will try to dispatch a tool of that name and fail — keep the CLI binary named `varve` and let the shim directory hold the other names.

On Windows a shim is a copy, so it does not follow `varve self-update`; re-run `varve shim install` after updating.

A shim asked for a tool the pinned layer does not carry REFUSES, exits 1, and runs nothing: no executable found on PATH is ever run through a shim, because that is the mixed-toolchain hazard varve exists to close. The refusal lists what you can do instead, and varve picks none of it for you. It names an executable of that name on PATH (the shim directory itself is skipped) with the exact command that runs it directly, outside the layer; and every installed layer that carries the tool, with the `varve.toml` lines (`layer`, plus `channel` or `realm` where they differ) that would select it. When neither exists, it says nothing else provides the tool. (REQ-SHIMFALLBACK-001; `varve run` refuses the same way.)
