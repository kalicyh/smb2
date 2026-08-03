# How much silence a watcher survives, measured

What ends a parked CHANGE_NOTIFY *on a dead link* is connection-wide silence, not a missed ECHO probe. This note records
what real servers actually do, because the two are wildly different numbers and only the first one decides anything.

Scope: everything below is about the link dying. A subscription that dies on its own while the link stays healthy is
invisible to every number here, by construction — see `src/client/CLAUDE.md` § The long-poll refresh cycle for the
separate mechanism that covers it.

Reproduce with `cargo run --release --example liveness_probe` (its header lists the knobs). It runs two connections
against the same server at once: a **measured** one (keepalive and response deadline off, one CHANGE_NOTIFY parked,
probes sent and timestamped by the harness so a late reply is still recorded) and a **shipping** one (every default
left alone, a real `Watcher` parked), so the input distribution and the end-to-end verdict come from the same minute of
the same server's life.

## The rule being measured

`Connection::await_long_poll` ends a watch only when `Inner::quiet_for` reaches the response deadline (30 s at the
defaults) *and* the keepalive is armed. `quiet_for` is fed by EVERY received frame, including a probe reply that
arrives after the keepalive already gave up on it. So the quantity that matters is the longest interval in which the
server put **nothing at all** on the wire — roughly five consecutive fully-unanswered probes at the 5 s cadence, not
one.

## QNAP TS-464, saturated with writes (2026-08-02)

24.4 GB pushed through `examples/write_storm` in five passes (400 files × 12.8 MB, 32-deep concurrency) at ~100 MiB/s
sustained, 400+ WRITEs outstanding and up to 2.9 s between file completions. A watch parked on a sibling directory, so
no change events kept its wire warm — the worst case.

- ECHO probes: **48 of 48 answered, every one inside the 5 s keepalive window.** Worst round trip 49 ms.
- Longest run of consecutive missed probes: **0**. The shipping connection's own counters agree: 50 probes sent, 0
  failures, 0 skipped.
- Longest silence gap: **5.03 s**, which is the probe cadence itself — the connection was never quiet longer than we
  waited before asking again.
- A lighter earlier run (4.8 GB, 12-deep) matched: 40 of 40 answered, longest gap 5.05 s.

An earlier single observation of this NAS dropping 1 probe in 3 under write load did not reproduce in 88 probes across
two loaded runs. Treat "a busy NAS drops probes" as possible but rare; ❌ don't treat it as reachable to six in a row on
this hardware.

## Raspberry Pi 4 / Samba 4.9.5, `smbd` suspended (2026-08-02)

`SIGSTOP` on every `smbd` is the deterministic version of the same question: it produces exact silence of a chosen
length while TCP stays `ESTABLISHED`, so sends keep succeeding and only the answers stop.

| Stall | Silence gap | Consecutive missed probes | Real `Watcher` |
|---|---|---|---|
| none | 5.00 s | 0 | fine |
| 20 s | 25.0 s | 3 | survives, correctly — under the 30 s bound |
| 90 s | 90.3 s | 17 | told at **30.1 s**, `Error::ServerUnresponsive` |

The 90 s row is also the regression this note exists for. Before `Watcher::next_events` was routed through
`Connection::await_response`, the same 90 s stall produced the same 17 missed probes and the watcher **survived** —
that is, stayed deaf forever on a session it had no way to learn was dead. `recv()` on a `WaiterGuard` is an unbounded
`oneshot` await; the long-poll bound lives one layer up. Pinned by
`fault_injection_tests::a_real_watcher_on_a_dead_server_is_told_instead_of_waiting_forever`.

## Headroom

The gap between what a healthy loaded server does (5 s) and what ends a watch (30 s) is 6×, and it is a gap in the
quantity that matters rather than in a proxy for it. ❌ Don't retune `RESPONSE_TIMEOUT` down without re-running this:
the margin is the whole reason the bound is safe to have.
