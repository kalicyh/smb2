#!/bin/sh
# NAS-side sampler for the SMB-listing probe (read-only observation).
# Usage: nas_sample.sh <label> <duration_seconds>
# Writes two TSV streams to /tmp/nas-probe/<label>.{iostat,arc}.tsv, both at 2s cadence.
#   iostat.tsv: epoch + `zpool iostat -Hlp zpool2` row (parseable; latencies in ns). Self-terminates (bounded count).
#   arc.tsv:    epoch + selected arcstats counters + /proc/stat cpu line (raw cumulative; deltas computed off-box).
set -u
LABEL="${1:?label}"
DUR="${2:?duration seconds}"
POOL=zpool2
ARC=/proc/lpl/kstat/zfs/arcstats
OUT=/tmp/nas-probe
mkdir -p "$OUT"
IOF="$OUT/$LABEL.iostat.tsv"
ARCF="$OUT/$LABEL.arc.tsv"
: > "$IOF"; : > "$ARCF"

# Stream 1: bounded, timestamped zpool iostat with latency+queue at 2s.
# Row 1 is the since-boot average (dropped in analysis); rows 2..N are true 2s intervals.
COUNT=$(( DUR / 2 + 2 ))
( zpool iostat -Hlp "$POOL" 2 "$COUNT" | awk '{print systime()"\t"$0; fflush()}' > "$IOF" ) &
IOPID=$!

# Stream 2: arcstats + cpu at 2s.
END=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$END" ]; do
  EPOCH=$(date +%s)
  VALS=$(awk '
    /^hits /{h=$3} /^misses /{m=$3}
    /^demand_metadata_hits /{dmh=$3} /^demand_metadata_misses /{dmm=$3}
    /^demand_data_hits /{ddh=$3} /^demand_data_misses /{ddm=$3}
    /^prefetch_metadata_hits /{pmh=$3} /^prefetch_metadata_misses /{pmm=$3}
    /^size /{sz=$3}
    END{print h"\t"m"\t"dmh"\t"dmm"\t"ddh"\t"ddm"\t"pmh"\t"pmm"\t"sz}' "$ARC")
  CPU=$(awk '/^cpu /{print $2"\t"$3"\t"$4"\t"$5"\t"$6"\t"$7"\t"$8}' /proc/stat)
  printf '%s\t%s\t%s\n' "$EPOCH" "$VALS" "$CPU" >> "$ARCF"
  sleep 2
done

wait "$IOPID" 2>/dev/null
# arc.tsv cols: epoch hits misses dmeta_h dmeta_m ddata_h ddata_m pmeta_h pmeta_m arcsize  cpu:user nice sys idle iowait irq softirq
echo "DONE $LABEL" >&2
