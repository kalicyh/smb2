//! Formatting helpers for the probe's text report.

use std::time::Duration;

use smb2::ListingTrace;

/// p50 / p90 / mean of a set of durations, in milliseconds.
pub struct Stats {
    pub p50: f64,
    pub p90: f64,
    pub mean: f64,
}

pub fn stats_ms(durs: &[Duration]) -> Stats {
    if durs.is_empty() {
        return Stats {
            p50: 0.0,
            p90: 0.0,
            mean: 0.0,
        };
    }
    let mut us: Vec<u128> = durs.iter().map(|d| d.as_micros()).collect();
    us.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = ((us.len() as f64 - 1.0) * p).round() as usize;
        us[idx] as f64 / 1000.0
    };
    let mean = us.iter().sum::<u128>() as f64 / us.len() as f64 / 1000.0;
    Stats {
        p50: pct(0.50),
        p90: pct(0.90),
        mean,
    }
}

/// Aggregate a serial phase-breakdown pass: per-phase stats plus totals.
pub fn summarize_phases(traces: &[ListingTrace], wall: Duration) -> String {
    let create: Vec<Duration> = traces.iter().map(|t| t.create).collect();
    let query: Vec<Duration> = traces.iter().map(|t| t.query_total()).collect();
    // First QUERY only, the one that carries entries for a small dir.
    let first_query: Vec<Duration> = traces
        .iter()
        .filter_map(|t| t.queries.first().map(|q| q.elapsed))
        .collect();
    let close: Vec<Duration> = traces.iter().map(|t| t.close).collect();
    let total: Vec<Duration> = traces.iter().map(|t| t.total()).collect();

    let entries: usize = traces.iter().map(|t| t.entries).sum();
    let round_trips: usize = traces.iter().map(|t| t.round_trips()).sum();
    let n = traces.len();

    let cs = stats_ms(&create);
    let qs = stats_ms(&query);
    let fqs = stats_ms(&first_query);
    let cls = stats_ms(&close);
    let ts = stats_ms(&total);

    let mut s = String::new();
    s.push_str(&format!(
        "  dirs={n}  entries={entries}  wall={:.1}s  serial dirs/s={:.1}  entries/s={:.0}\n",
        wall.as_secs_f64(),
        n as f64 / wall.as_secs_f64(),
        entries as f64 / wall.as_secs_f64(),
    ));
    s.push_str(&format!(
        "  round trips: {round_trips} total, {:.2}/dir avg\n",
        round_trips as f64 / n.max(1) as f64
    ));
    s.push_str("  phase              p50 ms   p90 ms   mean ms\n");
    s.push_str(&format!(
        "  CREATE           {:8.2} {:8.2} {:9.2}\n",
        cs.p50, cs.p90, cs.mean
    ));
    s.push_str(&format!(
        "  QUERY (1st)      {:8.2} {:8.2} {:9.2}\n",
        fqs.p50, fqs.p90, fqs.mean
    ));
    s.push_str(&format!(
        "  QUERY (all)      {:8.2} {:8.2} {:9.2}\n",
        qs.p50, qs.p90, qs.mean
    ));
    s.push_str(&format!(
        "  CLOSE            {:8.2} {:8.2} {:9.2}\n",
        cls.p50, cls.p90, cls.mean
    ));
    s.push_str(&format!(
        "  TOTAL (wire)     {:8.2} {:8.2} {:9.2}\n",
        ts.p50, ts.p90, ts.mean
    ));
    s
}
