# varve install [--from <src>]

Resolves the project pin, fetches from the source (a realm registry, an oci:// reference, an oci-layout archive, or a manifests+blobs dir), verifies the signature and every artifact digest against the trust root, and lays the layer down. Also auto-caches any baseline line-status the source carries. Fails closed on any verification failure.
