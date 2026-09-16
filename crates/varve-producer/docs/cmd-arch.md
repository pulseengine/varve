# varve-producer arch

Does a staged payload's architecture match the platform it would be deposited
under — without executing it?

```sh
varve-producer arch --file ./stage/meld --platform aarch64-apple-darwin
```

Reads the binary's own header (ELF machine, Mach-O CPU type, PE machine). It
never runs the file: a producer that executed a downloaded payload to find out
what it was would be running unverified code to decide whether to trust it.

The failure this prevents is a layer that installs cleanly and then cannot exec
— an x86_64 binary deposited under an aarch64 platform annotation verifies
perfectly, because the digest is correct. It is the wrong bytes for the right
digest.
