# varve self-update [--check] [--to <path>]

Updates varve itself: the running binary verifies its successor against the pinned trust root before replacement (old-verifies-new). Decides on artifact identity, not version strings, so a stale version degrades to a no-op instead of a loop. --check reports without changing anything.
