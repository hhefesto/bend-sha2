# sha2: SHA-256 (cryptohash-sha256)

FIPS 180-4's SHA-256 over bytes (`sha.sum`: the digest in hex; `sha.digest`:
its 32 bytes). What it means is the standard; `probe/Sha2.bend` checks the
standard's examples (and the empty message): "sha ok".

## This repository

Written for mugen-app (mugen's chat in a browser) as part of its Bend
backend, which replaced a Haskell one: a mention above of `backend/`,
`server/` or `server/test/compare.sh` is that app's. The libraries written
with it: [bend-wire](https://github.com/hhefesto/bend-wire), [bend-route](https://github.com/hhefesto/bend-route), [bend-json](https://github.com/hhefesto/bend-json), [bend-files](https://github.com/hhefesto/bend-files), [bend-md](https://github.com/hhefesto/bend-md), [bend-radix](https://github.com/hhefesto/bend-radix), [bend-text](https://github.com/hhefesto/bend-text), [bend-time](https://github.com/hhefesto/bend-time), [bend-entropy](https://github.com/hhefesto/bend-entropy), [bend-bcrypt](https://github.com/hhefesto/bend-bcrypt), [bend-bucket](https://github.com/hhefesto/bend-bucket).

**Using it.** Bend imports by path: clone this repository as `bend-sha2/`
beside your code,
and import it: `import ../bend-sha2/Sha2.bend as X`. In a Nix build, copy the flake's
source (or its `packages.default`) there.
The probe in `probe/` imports `bend-wire/` beside this one too.

**Checks** (`nix flake check`, with the pinned Bend 2.0.39):
`bend FILE.bend --check-only` on each module.

**License**: MIT (`LICENSE`).
