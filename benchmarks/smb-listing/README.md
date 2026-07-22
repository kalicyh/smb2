# SMB directory-listing probe

Instruments `smb2`'s directory listing against a real NAS to explain listing throughput: which phase of a listing
dominates (CREATE / QUERY_DIRECTORY / CLOSE), how throughput scales with in-flight depth on one TCP session versus
several, how warm (ARC-cached) and cold listings differ, and how much a bigger QUERY_DIRECTORY buffer saves on fat
directories.

Built to diagnose why Cmdr's background index scan of a QNAP NAS ran far slower than an earlier benchmark on the same
box. See [`docs/benchmark-findings.md`](../../docs/benchmark-findings.md) for the verdict.

For the NAS-side counterpart (disk/ARC/CPU counters sampled on the QNAP while this probe runs, which is what confirmed
the disk is *not* saturated by a single session), see [`scripts/`](scripts/).

**Read-only.** The probe only ever issues CREATE(dir) + QUERY_DIRECTORY + CLOSE. It never writes, renames, or deletes.

## Setup

It reads the same `config.toml` as the sibling [`benchmarks/smb`](../smb) harness (same TOML shape, so one file
describes the NAS for both). By default it loads `../smb/config.toml`; that file is gitignored, so in a worktree pass
`--config <abs-path-to-main-checkout>/benchmarks/smb/config.toml` or set `SMB_LISTING_CONFIG`.

## Running

```sh
cargo run --release -- --config ../smb/config.toml
```

It's a standalone crate (its own workspace, like `benchmarks/smb`), so `cargo run` from this directory is the way; it's
not part of the library workspace.

### Flags

- `--config <path>`: config file (default `../smb/config.toml`; or set `SMB_LISTING_CONFIG`).
- `--target <name>`: which target from the config (default: the first).
- `--root <path>`: share-relative directory to walk from (default: the share root). Use `/` or `\` separators.
- `--sample <n>`: directories for the serial phase breakdown and warm sweeps (default 200).
- `--windows <csv>`: in-flight window sizes for the throughput sweeps (default `1,8,32,64,128`).
- `--cold-slice <n>`: directories per fresh slice in the cold sweeps (default 60). Each window size and each session
  count in the cold sweeps gets its own disjoint, never-listed slice of this many dirs.
- `--session-window <n>`: total in-flight depth held constant across the multi-session sweeps (default 64).
- `--sessions <csv>`: TCP session counts for the multi-session sweeps (default `1,2,4`).
- `--fat <n>`: how many of the fattest discovered directories to use in the buffer sweep (default 5).
- `--buffers <csv-KiB>`: QUERY_DIRECTORY output-buffer sizes to compare, in KiB (default `64,256,1024`). Sizes above the
  server's negotiated max transact size are skipped.
- `RUST_LOG=debug` for verbose SMB protocol logs.

Release mode matters: the measurement compares wire time, so local overhead must be negligible.

## What it measures

1. **Discovery**: a breadth-first walk from `--root` that lists parent directories to enumerate their children, leaving
   the children unlisted. Those unlisted children are the cold sample (their own metadata was never read, so the
   server's ZFS ARC hasn't cached it). The cold pool is partitioned disjointly across every cold measurement so no
   measurement benefits from another's caching.
2. **Phase breakdown (serial, one connection)**: per-phase p50/p90/mean for CREATE, the QUERY_DIRECTORY loop, and CLOSE,
   run cold (pass 1) then warm (pass 2, same dirs) to show the ARC effect. Uses `Tree::list_directory_instrumented`.
3. **Query-buffer sweep**: each fat directory listed once per candidate buffer size, reporting round-trip count and
   timing, to size the win from raising the 64 KiB per-QUERY output buffer.
4. **COLD vs WARM throughput vs in-flight window (one TCP session)**: dirs/s at each window. Cold uses a fresh disjoint
   slice per window (the real index-scan scenario); warm reuses the cached sample (the protocol ceiling).
5. **COLD vs WARM throughput across N TCP sessions** at a fixed in-flight depth: does spreading the load over more TCP
   sessions beat a single session's ceiling, or is the disk the shared bottleneck?

A timestamped copy of the full text report is saved to `results/`.

## Crate instrumentation

The probe relies on `smb2::Tree::list_directory_instrumented`, which runs the exact same wire path as
`list_directory` (CREATE → QUERY_DIRECTORY loop → CLOSE) but returns a `ListingTrace` timing every round trip, and
accepts an optional QUERY_DIRECTORY output-buffer override. Both methods drive the same `query_directory_step`, so the
instrumented path can't drift from production.
