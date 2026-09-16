# What listening on a socket does and does not expose

This program accepts network connections. `varve` does not, and that difference
is the reason these are two binaries rather than one subcommand. What follows is
what the separation buys, and — more usefully — what it does not.

## It binds loopback only

The listener binds `127.0.0.1`, never `0.0.0.0`. A pinned document is a local
artefact; serving one to the whole network by default would be a surprising
thing for a tool like this to do, and "surprising" is the wrong property for
anything adjacent to a verification tool.

There is no flag to change this. If you want a document on the network, export
it and serve it with something built for that job.

## Path traversal is impossible here, not merely prevented

The pages are held **in memory**, read once out of the verified archive at
startup. This program never opens a file in response to a request. A request
path is a map lookup: it either names a member of the payload or it does not.

So there is no filesystem path to escape, no `..` to normalise, and no
canonicalisation bug to have. `/../../../../etc/passwd` is not blocked — it is
simply not a page in the document, and comes back 404 like any other typo.

That is a property of the design rather than of care taken in one function,
which matters because care can be lost by a later edit and a design cannot be
lost silently. There is a test asserting it, so a change to serving from disk
has to break that test first.

## The uncomfortable part: a document is an execution context

HTML and JavaScript are not inert data. A documentation payload is rendered by
your browser, and that browser will run whatever the page contains — from an
origin (`http://127.0.0.1`) that is more trusted than a random website.

varve verifies that the bytes are **the ones the realm signed**. It does not,
and cannot, verify that what those bytes do is harmless. Those are different
claims, and only the first one is varve's.

This is why the trust root that signs a document is worth thinking about. Today
one realm root signs everything a layer carries — compiler binaries, editor
extensions, SDK trees and documentation alike — so a key that can vouch for a
page your browser executes is the same key that vouches for your toolchain.
criticalup's `criticaltrust` scopes keys by role for this reason; varve does not
yet. It is tracked as **varve#148**, to be decided before the v1.0 root ceremony
rather than discovered after it.

If that matters to you today, the mitigation is the ordinary one: do not carry
documentation from a realm you would not accept binaries from.

## What it does not do

- It does not phone home. There is no network access at all after startup.
- It does not write anything. `varve export-docs` is the command that writes.
- It does not accept anything but `GET`. Other methods are answered 405 rather
  than interpreted.

## What varve verified before any of this

The layer is re-verified against its realm's trust root before a single page is
read. Serving the contents of a layer varve cannot vouch for would look
authoritative and be worthless — so if verification fails, nothing is served and
nothing is listening.
