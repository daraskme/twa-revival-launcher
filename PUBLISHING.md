# Source publication boundary

This repository publishes a reviewable subset of the released launcher source.
It does not grant rights to Creative Assembly, SEGA, Epic, or other third-party
materials, and is not a complete game or a standalone source build.

## Included

- Authored Python implementation, entry point, preferences template, and notices.
- The original signed stable launcher manifest, unchanged.
- Release file names, lengths, and hashes for comparison with a separately
  obtained release. Hash records do not contain the referenced file contents.
- Repository documentation and a standalone verifier.

Published release files retain their exact bytes. Interoperability identifiers
and references used by the implementation remain in the source; this does not
include the extracted catalog tables or grant rights to the game itself.

## Excluded

- Game executables, DLLs, archives, models, textures, audio, video, and translations.
- Extracted or provenance-unverified catalog data, including all eleven
  `catalog/*.json` files listed explicitly in `verify_release.py`.
- Four source files held because they contain original game instruction sequences
  or embedded game-data mappings: `tools/build_native_specialization_binding.py`,
  `tools/native_fixed_family_mapper.py`, `server/local_stack.py`, and
  `server/native_postbattle_maps.py`. Their authored logic can be prepared
  separately once these inputs are separated from the code.
- Bundled third-party runtimes and SDK binaries.
- Credentials, private keys, account configuration, user diagnostics, captures,
  local deployments, and QA records.

The signed manifest still lists excluded update objects. Removing those records
would invalidate its release signature. The verifier checks the complete signed
file list against the release metadata, and checks that the excluded data is
absent from this checkout. It does not fetch or recreate excluded files.

Earlier commits contained catalog data and some of the held source files. Public
`main` now starts with a fresh source-only history that does not inherit those
commits. Copies in forks, old clones, pull-request references, and caches are not
erased by replacing `main`. Contributors should start from the new history and
reapply reviewed changes without merging the old ancestry back into the project.

## Repository layout

Keep this launcher repository focused on client-side source and release
verification. Keep reviewed, unreleased source changes on an explicitly labelled
QA branch or draft pull request until the signed production snapshot is ready.
The `server/` directory here is the local compatibility service
shipped with the launcher, not the hosted backend.

Prepare hosted matchmaking, relay, and API implementation in a separate server
repository. It has its own deployment/configuration, data requirements, tests,
and release schedule. Link compatible server and launcher versions in release
notes rather than copying private deployment trees into this repository.

## Before publishing another snapshot

1. Select an actually released ZIP and verify its recorded SHA-256 and signed
   stable manifest. Do not label a QA build as production.
2. Export an explicit list of reviewed source files; never recursively add an
   installed game, runtime, working directory, or extracted data directory.
3. Preserve source bytes and original signatures. Update the verifier's version,
   ZIP digest, and explicit exclusions together.
4. Check for credentials, embedded game content, binaries, unexpected files, and
   required third-party notices; inspect the complete staged Git diff.
5. Run the standalone verifier against the checkout and original ZIP. Confirm
   it rejects modified source, changed signatures, and an excluded catalog file.

The existing read-and-verify publication policy remains unchanged: no software
license is granted for project code. A broader reuse license requires a separate
decision; third-party notices must be preserved regardless.

## Keeping the repository current

For each launcher change, update the reviewed source branch and its draft pull
request when the QA candidate is prepared. State what changed, what has actually
been tested, and which release checks remain open. Do not advertise a candidate
as the current download or substitute unsigned metadata for a release signature.
The QA branch retains the production verifier as a reference: its 0.2.43
source-hash check is expected to fail against changed candidate source. Run that
verifier on `main` when checking the current production release.

When production is released, complete the same pull request with the original
signed stable manifest, complete release inventory, exact ZIP digest, matching
verifier constants and current README. Run the positive and exclusion/tamper
checks before merging it into `main`. Review the server and launcher separately;
copy only the explicit source allowlist and never merge private or retired Git
history. This is a maintainer release step, not an unattended upload job.

## Public verification keys and private signing keys

The Ed25519 public verification key is published in `companion/trusted_keys.py`
and pinned independently by `verify_release.py`. Public keys can be stored in
Git and distributed with the launcher. Pin a trusted key through an independently
verified channel; a manifest must not be allowed to choose an arbitrary new key.

Private signing keys must remain outside this repository, including its issues,
Actions logs, releases and encrypted files committed to Git. A Windows DPAPI
copy is useful for the local signing account but is not a portable recovery
backup. Maintain a separately encrypted, OS-independent offline backup of the
same signing key, with its recovery password stored separately. Test recovery by
signing a harmless test message and verifying it with the already published
public key before relying on the backup. Recovery should preserve key identity;
changing the release key requires a separate trust-migration plan.
