# varve keygen --out <FILE> [--pub <FILE>]

Mints a signing key and prints its public half — the value a realm pins as `trust-root`.

A varve signing key is **128 hex characters**: a 32-byte ed25519 seed followed by its 32-byte public key. The public half alone is 64 hex characters, and that is what consumers pin. Without this command there was no route from a key to that value, so an organisation could not stand up its own realm at all.

The key file is written mode 0600 and `keygen` refuses to overwrite an existing one. `--pub` also writes the public half to a file; without it the public half is printed, and `varve pubkey` re-prints it any time.

Guard the secret half the way you would any signing key: it is the whole of a realm's authority until a ceremony replaces it.
