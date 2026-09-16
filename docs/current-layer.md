# `docs/current-layer.txt`

The layer id the documentation uses in **pin examples** — the values a reader
copies into their own `varve.toml`.

One file, because the alternative is the same layer id written in a dozen
places and silently going stale in eleven of them. The README pinned
`2026.08.2` for four releases after it stopped being current, which is worse
than showing nothing: a reader who copies a stale pin gets an old toolchain and
no indication anything is wrong, and varve will happily verify it, because it
*is* a good layer — just not the one they meant.

`the_docs_pin_the_layer_they_say_they_do` asserts every pin example matches
this file. Changing the example layer is one edit plus a green test.

This is not the same thing as *illustrative* layer ids. A command example like
`varve archive 2026.07.0 ./core` teaches a shape and is not copied as
configuration; those are deliberately left alone. The rule is narrow on
purpose: it covers values a reader will paste into a file that then governs
their build.
