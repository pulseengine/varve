# varve shim install

Installs PATH dispatchers that resolve the pin from the invocation's working directory and exec the right binary — switching projects is just cd.

A shim IS the varve binary, reached under another name: on unix a symlink, on Windows a copy. varve looks at the name it was invoked as and dispatches that tool. There is no shell script and no shell, so nothing on the dispatch path parses a string, and the dispatch costs one process instead of two. Because a symlink resolves to whatever varve currently is, shims do not go stale when varve updates itself.
