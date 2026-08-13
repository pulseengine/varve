# Layers

A layer is one signed, dated bundle of tools and artifacts — `YYYY.MM.P`. The
initial deposit of a line is `.0`; a patch inside a frozen line is `.1`, `.2`, …
Layers are content-addressed by their signed manifest digest and coexist in the
core, so switching a project between layers costs no download — it is a pin edit.
Every layer carries a monotonic release counter and issued-at inside the signed
payload, so a stale-but-valid layer cannot be passed off as current.
