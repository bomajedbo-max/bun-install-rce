# RCE in `bun install` 1.3.x via `package.json` `bin` stack buffer overflow

Full public disclosure of **GHSA-w6m4-cghj-h6wm**, reported privately to the Bun team and
unacknowledged for ~30 days despite their security policy's 5-day acknowledgment commitment
(github.com/oven-sh/bun/security/policy). Published by the reporter.

## Summary

`bun install` is vulnerable to a stack buffer overflow via a `package.json` `bin` value longer
than the internal 4KB path buffer. The overflow in `_joinAbsStringBuf`
(`src/resolver/resolve_path.zig`) walks up the stack over saved registers and the return
address. This is not just a crash: the conditions for control-flow hijack are all present, and
the reporter verified end-to-end code execution with a working PoC.

`--ignore-scripts` does **not** mitigate: the overflow happens in bin-link normalization,
independent of script execution.

## Affected versions

| Version | Status |
|---|---|
| 1.3.1 - 1.3.14 | Vulnerable, verified. 1.3.14 is the final Zig release; 1.3.15 never shipped. |
| < 1.3.1 | Likely affected (same overflow class as silently-fixed #27492, Feb 2026), unverified. |
| 1.4.0+ | Not affected, but only because 1.4 is the Rust rewrite. The vulnerable Zig code was never patched and never will be (#39658 remains unmerged). |

**There is no fixed version within 1.3.x. Migration to 1.4.x is the only remedy.**

## Root cause

`_joinAbsStringBuf` uses a fixed `MAX_PATH_BYTES * 2` stack scratch with the input length
unchecked; the destination copy is guarded by an equality test (`cmp $0x2000, %r12; jne`),
not a bounds check. Entry point: bin-link normalization of `package.json` `bin` values
(`src/install/bin.rs`), reached by `bun install` after extraction, including from a
file/tarball dependency.

## Why this is exploitable (not just a panic)

The bug is tracked upstream as "panic" issues, so to be explicit about severity:

- The overflowing data is **fully attacker-controlled**: both content and length come from the
  `bin` string in the package's `package.json` (the PoC uses ~36KB).
- It reaches and **overwrites saved registers and the return address** on the way up the stack.
- The target is a **non-PIE binary** (e.g. `bun-linux-x64-baseline`): code addresses are fixed,
  no ASLR defeat required.
- The one constraint does not prevent exploitation: the value passes bun's UTF-8 validating
  copier, so payload bytes must be <= 0x7F (NUL is fine via JSON `\u0000`). In the affected
  builds the relevant code addresses satisfy this, so a ROP chain built from the `bin` value
  itself works.
- No race, no brute force: the overwrite is deterministic for a given install path.

With return-address control, controlled data, and fixed code addresses, the standard result is
a ROP chain that calls `execve("/bin/sh", ...)` with attacker arguments, i.e. arbitrary command
execution as the user running `bun install`. The reporter built and verified exactly that.
Per standard practice, chain internals beyond the trigger are held back from this publication;
the trigger and full analysis are below.

## Reproduction (overflow trigger)

```sh
mkdir -p pkg/node_modules/@poc/x && cd pkg
cp /path/to/poc.tgz node_modules/@poc/x/bundle.tgz
echo '{"name":"victim","version":"1.0.0","dependencies":{"@poc/x":"./node_modules/@poc/x/bundle.tgz"}}' > package.json
bun install --ignore-scripts     # bun 1.3.1
```

`poc.tgz` contains one package:
`{"name":"@poc/x","version":"1.0.0","bin":{"cli":"<36,153-byte value>"}}`.

The install process crashes with the corrupted stack; on the baseline build the crash is
replaced by the shell command staged in the payload.

This repository's `poc/build_poc.py` regenerates `poc.tgz` (parameterized by length).

## Impact

Any user of bun 1.3.x who installs dependencies they don't fully control is exposed, including
with `--ignore-scripts`:

- Multi-tenant services that install user-supplied packages (confirmed: code execution as root
  in a containerized multi-tenant install service during reporter testing).
- CI/CD runners installing dependencies from untrusted PRs.
- Supply chain: a dependency (direct or transitive) carrying the oversized `bin` value.
  Registry-distribution vector not verified; the PoC uses a file/tarball dependency.

## Mitigation

- Migrate to bun 1.4.x.
- Do **not** rely on `--ignore-scripts`.
- In 1.3.x environments, audit lockfiles for `file:`/tarball dependencies.

## Disclosure timeline

- **2026-09 (late)**: Privately reported via GitHub private vulnerability reporting
  (GHSA-w6m4-cghj-h6wm), including the demonstration payload and full analysis.
- **~30 days**: No acknowledgment, no triage, 0 comments. Bun's own security policy commits to
  acknowledgment within 5 days via security@bun.com.
- **2026-10-26**: This public disclosure published by the reporter.

## Credit

Reported by Abdullah Ghanamm ([@bomajedbo-max](https://github.com/bomajedbo-max)).

## References

- GHSA-w6m4-cghj-h6wm (private report, unacknowledged)
- Silently-fixed sibling class: oven-sh/bun#27492 (Feb 2026)
- Unmerged fix for the vulnerable path: oven-sh/bun#39658
- Bun security policy: github.com/oven-sh/bun/security/policy
