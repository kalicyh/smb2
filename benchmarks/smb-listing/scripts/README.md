# NAS-side sampler

`nas_sample.sh` runs **on the QNAP** (not the Mac) to capture ground-truth disk, ARC, and CPU counters while the
`smb-listing` probe drives load from the client. It answers what the client side can only infer: is the raidz1 HDD pool
actually saturated during a cold listing, does the ARC miss rate explain cold-vs-warm, and is anything CPU-bound. The
NAS-side findings it produced are in [`docs/benchmark-findings.md`](../../../docs/benchmark-findings.md) (the
2026-07-22 "NAS-side ground truth" section).

**Read-only.** It only reads `zpool iostat`, `/proc/lpl/kstat/zfs/arcstats`, and `/proc/stat`. No writes outside
`/tmp/nas-probe` on the NAS, no config changes, no service restarts.

## Usage

```sh
# On the NAS (copy it over first, e.g. scp scripts/nas_sample.sh naspi:/tmp/):
sh /tmp/nas_sample.sh <label> <duration_seconds>
```

Keep the SSH session open for the whole duration (QNAP BusyBox has no `nohup`/`setsid`, so a backgrounded copy dies on
disconnect). The simplest driver: start it from the client in one terminal, run the probe in another, then collect
`/tmp/nas-probe/<label>.{iostat,arc}.tsv`.

It writes two 2-second-cadence TSV streams:

- `<label>.iostat.tsv`: epoch + `zpool iostat -Hlp zpool2` row (parseable; rates are per-second, latencies in ns). Row 1
  is the since-boot average and is dropped in analysis; rows 2..N are true 2 s intervals.
- `<label>.arc.tsv`: epoch + selected `arcstats` counters (hits, misses, demand-metadata hits/misses, size) +
  `/proc/stat` cpu line. Counters are raw cumulative; take deltas between rows off-box.

## Correlating with the probe

Pipe the probe's stdout through a per-line epoch stamp so each phase header lands on the same clock as the samples:

```sh
./target/release/smb-listing-probe --config ../smb/config.toml --root photos ... \
  | perl -ne 'BEGIN{$|=1} print time(), "\t", $_'
```

Then slice the NAS TSVs by each phase's epoch window.

## Gotchas (QNAP TS-464, QuTS/ZFS)

- Arcstats live at `/proc/lpl/kstat/zfs/arcstats` here, **not** the usual `/proc/spl/kstat/zfs/arcstats` (QNAP renamed
  `spl` to `lpl`).
- `iostat -x` cannot see the raidz1 HDDs: QNAP's `qzfs` layer hides the raw `/dev/sd*` devices (only NVMe and eMMC show
  up), so there is **no per-disk %util** for the pool. Use `zpool iostat -l` `disk_wait` latency as the saturation proxy
  instead.
- The SMB server is **ksmbd** (kernel threads `ksmbd-*`), not Samba, so SMB CPU shows up as kernel `sys`/`softirq` time,
  not a userland `smbd` process.
