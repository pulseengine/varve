# varve list

Lists every layer present in the local core, with channel and digest. Read-only; never mutates the core.

A layer installed under a realm partition (`$VARVE_ROOT/realms/<fingerprint>`) is tagged `realm=<name>` (or the fingerprint, if no realms file names it). A layer with no `realm=` tag is one `list` found at the top of the core (`$VARVE_ROOT/core`) — the pre-realm layout. If any such entries are listed, `list` prints one note naming how many and where: they belong to no realm, so no realm's root vouches for them, and `varve` does not use them except through a realmless pin naming them explicitly — never as a fallback. The note is informational only; `list` never deletes anything.
