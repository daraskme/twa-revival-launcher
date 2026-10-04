"""Pinned Ed25519 public keys for update-manifest signature verification.

Both mappings use ``publicKeyId -> 32-byte Ed25519 public key`` (64 hex
characters). ``TRUSTED_KEYS`` is the local updater/dev-CLI trust set;
``RELEASE_TRUSTED_KEYS`` is the separate fail-closed release startup trust
root. companion/manifest.py refuses an unknown id or bad signature.

## "dev-2026-09" (DEV KEY -- do not use for a real rollout)

This is a placeholder key for local development and companion/tests/, not a
production secret. Its private seed is NOT random and NOT secret: it is
sha256(b"twa-revival-dev-manifest-key-2026-09"), so anyone with this source
tree can reconstruct it and sign a manifest that this dev key accepts. That
is intentional -- it lets tests build valid signed fixtures without shipping
a private key file -- but it also means a manifest signed with this key
proves nothing about who published it. See
companion/tests/_dev_signing.py for the seed derivation used by tests.

## Rotation

Before any real (staging/production) deployment:
  1. Generate a real key pair with a real random 32-byte seed, offline, on a
     machine that will hold the private half (a HSM/secrets manager, not
     this repo). `companion/_ed25519.generate_keypair(seed)` or `pynacl`/
     `cryptography` can both produce it; only the *public* half goes in
     ``RELEASE_TRUSTED_KEYS`` below.
  2. Add it under a new id, e.g. "prod-2027-01" (date-suffixed so a rotation
     history is legible at a glance). Do not reuse "dev-2026-09".
  3. Keep the previous production id in ``RELEASE_TRUSTED_KEYS`` until every companion
     build that might still be running has fetched at least one manifest
     signed with the new key (i.e. until the rollout channel's minimum
     client version excludes anyone who could still see the old key).
  4. Only then remove the retired id. Removing a key immediately breaks
     verification for anyone still offered a manifest signed with it.
  5. Sign manifests in the secured offline/release-publisher environment, then
     upload only the already-signed manifest and payloads. Never place the
     release private key in the Worker, R2, this repository, or a client build;
     this file only ever holds public keys.
"""
from __future__ import annotations

# Public, signed downloads never require a game session or Epic credentials.
PUBLIC_DOWNLOAD_ORIGIN = "https://downloads.darask.me"

TRUSTED_KEYS: dict[str, str] = {
    # DEV ONLY -- see module docstring. Not a secret; do not treat it as one,
    # and do not add a real production key alongside it without reading the
    # rotation notes above.
    "dev-2026-09": "a471d9e62d9c0a1cb7abd46c80a76ec3cbc26bfd5ea6c47827075e1b3c01d3bb",
}

# Generated for public distribution on 2026-09-14. The private half is retained
# outside the repository in the publisher's Windows DPAPI key store. The
# startup gate never falls back from this set to TRUSTED_KEYS, because the
# latter intentionally contains a publicly reproducible test key.
RELEASE_TRUSTED_KEYS: dict[str, str] = {
    "2751aa46b0af141c": "b6f75c29cdefdb770c0379d1195694e2696c20421ce305b0400e9193dabda4a5",
}
