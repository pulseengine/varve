# varve-producer forge

Which forge would this run ingest from, and which authority is expected to have
signed it?

```sh
varve-producer forge
GH_HOST=github.acme.example varve-producer forge
```

Printed **before anything is fetched**, because a wrong issuer fails closed but
confusingly: the download succeeds, the signature check refuses, and the message
is about a certificate rather than about the host you meant.

`GH_HOST` is what `gh` itself uses, so varve reads the same variable rather than
inventing a second one. `VARVE_OIDC_ISSUER` overrides the expected OIDC issuer
for an instance that does not follow the default.
