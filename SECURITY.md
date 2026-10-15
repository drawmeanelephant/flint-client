# Security policy

Do not open a public issue containing a signing seed, auth secret, private
source/store, or an exploitable vulnerability. Use GitHub's private
vulnerability reporting when enabled, or contact the repository owner
privately through their GitHub profile to agree on a secure channel first.

The client stores signing keys as exclusive mode-0600 files and wipes
secret buffers. Prefer key names and file paths. Literal secrets in argv
or environment variables can leak through process inspection/history.
Never use the public conformance vectors as real keys.

FLINT-SYNC/1 authenticates and verifies Changes but raw TCP is not encryption.
Use a secure authenticated tunnel for untrusted networks. Verification proves
integrity/author identity, not that an author is trusted.

Review code touching canonicalization, crypto, file permissions, safe writes,
replay bounds, or remote operations against the ADR/spec. CI scans for leaked
secrets and checks workflow configuration; these are not a complete security
audit of the Zig implementation. See [maintainer setup](docs/maintainers.md)
for native scanning, review integrations, and required owner actions.
