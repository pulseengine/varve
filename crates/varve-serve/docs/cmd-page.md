# varve-serve page

Show one page of a verified documentation payload, as text.

```sh
varve-serve page varve-core-api varve_core/store/struct.Store.html
```

This is the command an `ask` hit prints in its `read` line. HTML has its markup
removed; Markdown and other files print as stored.

Only members of the verified payload can be shown. A path that is not a member,
including every `../` path, is refused with a non-zero exit and an error naming
the document; a stray file planted in the store is not a member and never
appears.
