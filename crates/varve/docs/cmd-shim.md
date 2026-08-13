# varve shim install

Installs PATH dispatchers that resolve the pin from the invocation's working directory and exec the right binary — switching projects is just cd.

A shim IS the varve binary, reached under another name: on unix a symlink, on Windows a copy. varve looks at the name it was invoked as and dispatches that tool. There is no shell script and no shell, so nothing on the dispatch path parses a string, and the dispatch costs one process instead of two. Arguments pass through as raw bytes, so a filename that is not valid UTF-8 reaches the tool unchanged.

A consequence worth knowing (rustup behaves the same way): the binary must be named `varve` to offer the CLI. A copy called `varve-0.19` or `myvarve` will try to dispatch a tool of that name and fail — keep the CLI binary named `varve` and let the shim directory hold the other names.

On Windows a shim is a copy, so it does not follow `varve self-update`; re-run `varve shim install` after updating.
