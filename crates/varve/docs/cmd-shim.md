# varve shim install

Installs PATH dispatchers that resolve the pin from the invocation's working directory and exec the right binary — switching projects is just cd.

A shim IS the varve binary, reached under another name: on unix, a symlink. Where only a copy is possible — Windows — `shim install` REFUSES rather than writing one, because a copy binds to the varve that existed when you ran it: `self-update` would replace the binary and leave every shim running the old verification and refusal logic, with nothing saying so. Use `varve run <tool>` there; it resolves the pin on every invocation and is never stale. Which mechanism should replace the copy is open on purpose (DD-031, varve#197). varve looks at the name it was invoked as and dispatches that tool. There is no shell script and no shell, so nothing on the dispatch path parses a string, and the dispatch costs one process instead of two. Arguments pass through as raw bytes, so a filename that is not valid UTF-8 reaches the tool unchanged.

A consequence worth knowing (rustup behaves the same way): the binary must be named `varve` to offer the CLI. A copy called `varve-0.19` or `myvarve` will try to dispatch a tool of that name and fail — keep the CLI binary named `varve` and let the shim directory hold the other names.

On Windows a shim is a copy, so it does not follow `varve self-update`; re-run `varve shim install` after updating.

A shim asked for a tool the pinned layer does not carry REFUSES, exits 1, and runs nothing, unless YOU have opted in from a file outside every repository (next section). By default no executable found on PATH is run through a shim, because that is the mixed-toolchain hazard varve exists to close. The refusal lists what you can do instead, and varve picks none of it for you. It names an executable of that name on PATH (the shim directory itself is skipped) with the exact command that runs it directly, outside the layer; and every installed layer that carries the tool, with the `varve.toml` lines (`layer`, plus `channel` or `realm` where they differ) that would select it. When neither exists, it says nothing else provides the tool. (REQ-SHIMFALLBACK-001; `varve run` refuses the same way, always.)

## Passthrough: running a tool the layer does not carry (opt-in)

A tool installed locally, that the pinned layer has no opinion about, is unusable behind a shim that refuses it (varve#273). You can allow a shim to fall through to it, with a USER-level file, `$XDG_CONFIG_HOME/varve/config.toml` (an absolute `XDG_CONFIG_HOME`; otherwise `~/.config/varve/config.toml`):

```toml
[shim]
passthrough = ["just", "direnv"]   # these tools; or ["*"] for any tool the layer lacks
```

The rules (REQ-PASSTHROUGH-001):

- **Only you can turn it on.** A `varve.toml` key for it is a parse error, and a config file that lies inside a repository (any directory above the working directory holding a `varve.toml`, `.git`, `.hg`, `.jj` or `.svn`, symlinks resolved) is ignored with a note in the refusal, even if `XDG_CONFIG_HOME` points at it: that variable can be set by a repository's own `.envrc`. A version-controlled `$HOME` therefore refuses a config under it (the default `~/.config/varve/config.toml` is inside that repository); the workaround is to point `XDG_CONFIG_HOME` at a directory outside any repository. An invalid file (an unknown key such as a misspelt `passthru` included) grants nothing and the refusal says why.
- **The layer always wins.** A tool the pinned layer carries is never passed through, whatever the file says; the layer's own binary runs (REQ-SHADOW-001). "Carries" means every tool in the pinned layer's manifest, and in every layer it includes or composes, whether or not the pin's `tools` list selects it; names are compared ignoring ASCII case, so `PROBE` is `probe` on every platform. If those manifests cannot be read, passthrough is refused. The file is not even read for it.
- **It is only for shims.** `varve run` refuses as before.
- **It never loops.** The PATH search skips the shim directory and any other link to varve, so a PATH whose only match is a shim refuses. A copy or hardlink of the binary cannot be recognised that way, so a passthrough runs its tool with `VARVE_PASSTHROUGH=<tool>` set, and a shim that finds it already set for its own tool refuses with a "passthrough loop" error. Only absolute PATH entries are searched: an empty entry, `.` and any relative one mean the working directory, which is the repository, and are skipped.
- **It is announced.** Each passthrough run prints one line on stderr, `varve: passthrough: '<tool>' is not part of layer <layer>; running <binary> outside the layer (not verified by varve; allowed by <file>)`, and then the tool is the process: its exit code and stdout are its own, and `VARVE_LAYER` is not set for it. Control characters in the binary's path are escaped, so the notice is always one line.
- **It is recorded.** `varve status` lists the active passthroughs (and `--json` has an `ambient_tools` object: `allowed`, `source`, `problem`, `active`); `varve verify` prints the allowed tools; and exports (`.varve-export.json` `ambient_tools`) and attestations (the signed statement's `ambient_tools`) carry what the producing session allowed. Records say what a session PERMITTED, not that anything ran. A session that allowed nothing writes no such field, so its stamps and statements are byte-for-byte what they were. `varve verify` also prints the signer's allowed tools under each attestation the layer carries. Readers older than this feature ignore the field; readers since fail closed on a field they do not know.
- **What the record is not.** The export stamp (`.varve-export.json`) is unsigned, so its `ambient_tools` record can be stripped by anyone who can edit the directory; the signed attestation is the durable record. A record also reflects the configuration when the export ran (or the statement was signed), not the configuration now.
