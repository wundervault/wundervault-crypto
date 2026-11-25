# Vendored: argon2-browser

    package   argon2-browser
    version   1.18.0
    license   MIT (see argon2-browser.LICENSE)
    source    npm, `npm pack argon2-browser@1.18.0`
    file      dist/argon2-bundled.min.js (WASM inlined — no second request)
    sha256    77c64b946baf1a5116dc591f4b9965d636b1b455f75edd2d4a587cb75e01687b

## Why it is vendored rather than loaded from a CDN

This file derives the key that decrypts the vault. Anyone able to change it can read every
passphrase typed into the site. A CDN is a third party with that power, on a page whose whole
claim is that we cannot read your vault — so it is served from our own origin, where changing
it means compromising us, which an attacker would have to do anyway.

## Verified, not assumed

Checked against the reference implementation (Python `argon2-cffi`, which wraps upstream
libargon2) in a real Chromium. Four parameter sets, byte-identical output each time:

    t=1 m=47104 p=1   MATCH   <- THE TUPLE ACTUALLY SHIPPED (ARGON2ID_KDF)
    t=2 m=46080 p=1   MATCH
    t=2 m=65536 p=1   MATCH
    t=3 m=65536 p=4   MATCH
    t=1 m=19456 p=1   MATCH

The first line was added after review pointed out that the shipped tuple was measured for
SPEED but never checked for CORRECTNESS — the four originally verified sets were all
different. A defect specific to the chosen parameters would have wrapped vaults that no
reference-compatible client could ever open. **Whenever ARGON2ID_KDF changes, the new tuple
goes in this list before it ships.**

## Measured, not estimated

Real Chromium, CPU throttled through CDP (Lighthouse models a mid-tier phone at 4x, a low-end
one at 6x). These are OWASP's equivalent-strength parameter sets:

| parameters | desktop | mid 4x | low 6x |
|---|---|---|---|
| **m=46MiB t=1 p=1  (chosen)** | 280 ms | 776 ms | 1184 ms |
| m=45MiB t=2 p=1 | 356 ms | 1566 ms | 2376 ms |
| m=19MiB t=2 p=1 | 151 ms | 656 ms | 984 ms |
| m=12MiB t=3 p=1 | 139 ms | 611 ms | 932 ms |

**m=46MiB t=1 p=1** is OWASP's first choice and the best trade here: among options of equal
rated strength, the high-memory one costs least on a slow device, and memory is what resists
GPUs and ASICs — extra passes are cheap for an attacker in a way extra memory is not.

For comparison, PBKDF2-SHA256 600k measured 208 ms in the same browser. It does not change
under CPU throttling because SubtleCrypto runs it off the throttled thread, so that figure
understates its real cost on a phone and the gap is narrower than the table suggests.

**Still not a phone.** Throttling does not model memory bandwidth or thermal behaviour, which
is exactly what a 46 MiB allocation meets on real hardware. Confirm on a device before this
reaches everyone.

## Updating

Re-run `npm pack argon2-browser@<version>`, re-run the correctness check against
`argon2-cffi`, re-measure, and update the sha256 above. Do not update without re-verifying:
a silently wrong Argon2id locks every account out of its own vault.
