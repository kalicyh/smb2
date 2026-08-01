# Client -- high-level SMB2 API

Entry point for most users. `SmbClient` wraps `Connection` + `Session` and provides convenience methods for file operations.

## Key files

| File | Purpose |
|---|---|
| `mod.rs` | `SmbClient`, `ClientConfig`, `connect()` shorthand |
| `connection.rs` | `Connection` -- message sequencing, response deadline, signing, encryption, `execute` / `execute_compound` |
| `credits.rs` | `CreditPool` -- the connection-wide credit budget and the send-side gate |
| `session.rs` | `Session::setup()` -- NTLM auth, key derivation, signing/encryption activation |
| `tree.rs` | `Tree` -- share connection, file CRUD, compound and pipelined I/O |
| `stream.rs` | `FileDownload` / `FileReader` (random-access positioned reads) / `FileUpload` / `FileWriter` (owns `Connection` + `Arc<Tree>`, `'static`) / `open_file_writer` / `open_file_reader` -- streaming and positioned I/O |
| `watcher.rs` | `Watcher` -- directory change notifications via CHANGE_NOTIFY long-poll |
| `pipeline.rs` | `Pipeline` / `Op` / `OpResult` -- batched concurrent operations (the core feature) |
| `shares.rs` | Share enumeration via IPC$ + srvsvc RPC |
| `dfs.rs` | DFS referral IOCTL helper, `DfsResolver` with TTL-based referral cache |
| `copy.rs` | Server-side copy (`FSCTL_SRV_COPYCHUNK`): resume-key + copychunk primitives, batched range/whole-file convenience, `ResumeKey` / `CopyChunk` / `ServerSideCopyLimits` public types |

## Layering

```
SmbClient  (owns Connection + Session, stores credentials for reconnect)
  Connection  (TCP transport, credits, message IDs, signing, encryption)
    Session   (NTLM auth, key derivation -- setup mutates Connection)
      Tree    (share-level ops, borrows &mut Connection for each call)
  extra_connections  (HashMap<String, ConnectionEntry> for DFS cross-server)
  dfs_resolver       (DfsResolver with TTL-based referral cache)
```

All `Tree` methods take `&mut Connection` as a parameter. `SmbClient` convenience methods use `connection_for_tree(tree)` to route through the correct connection (primary or DFS extra connection) based on the tree's `server` field.

## Connection and credits

Full model, rationale, and the incident behind it: `credits.rs` module docs.

- **Credits are reserved on send, never on receipt.** `CreditPool` (`credits.rs`) is a `Semaphore`, one permit per unspent credit; `Inner::reserve_credits` takes the charge before the bytes go out, and only a `CreditResponse` grant puts permits back. Accounting on the response instead makes every in-flight request invisible, which is how concurrent streams over one connection out-spend the server's window and get themselves silently cut off.
- **The budget is per connection**, on the `Arc<Inner>` every clone shares. ❌ Don't add a per-stream credit check: `conn.credits()` is a gauge, not a gate, and second-guessing the pool can only under-send. The pipelined loops queue against `MAX_PIPELINE_WINDOW` alone for exactly this reason.
- Multi-credit requests (reads/writes > 64 KB) charge `ceil(payload_size / 65536)` credits and use that many consecutive `MessageId` values. Gaps in `MessageId` sequences cause the server to drop the connection.
- A short send parks until a grant arrives, bounded so it can't become a starvation hang: nothing outstanding to fund the wait → immediate `Error::CreditStarvation`; connection death → `CreditPool::close` wakes every waiter; otherwise the 30 s `set_credit_wait_timeout` deadline.
- Every request asks for its own charge back plus enough to reach a 512-credit target. ❌ Don't flatten this to a constant: asking for less than the charge lets the window shrink to nothing and serializes every transfer.
- `STATUS_PENDING` interim responses carry credits but the request isn't done -- keep waiting.

## The send path: a writer task, and why

`Connection` never lets a caller touch the socket. `send_and_count` hands a **whole frame** to an `mpsc` queue and waits
for the writer task's ack; `writer_loop` owns the transport's write half and is the only thing that writes.

- **Bounded.** Each frame gets `set_send_timeout` (60 s default) to reach the socket, then `Error::SendTimeout` and the
  connection is torn down. Nothing else in this crate bounds this: the response deadline and the credit deadline both
  start once the server has been asked, so a socket that stops accepting writes is invisible to them. That is exactly
  how a 2026-08-01 Cmdr wedge sat frozen for 40 minutes with ~700 requests "in flight" and zero bytes on the wire.
- **Torn down, not retried, on failure.** A write abandoned partway has already put bytes on the wire, so the stream
  can't be resynced. A frame rejected *before* any byte went out (oversized) is the caller's problem alone and leaves
  the connection alive.
- **Whole frames only.** `TcpTransport::send` writes a 4-byte length header and then the body. A caller cancelled
  between the two used to leave a header with no body on the wire and every later frame landed inside it — and
  consumers cancel constantly (a user aborting a copy). Queuing the frame as one message makes that unreachable.
- ❌ **Don't add a second writer, or let a caller call `TransportSend::send` directly.** Frames would interleave.
- The queue is bounded (`WRITE_QUEUE_DEPTH`); `send_queue_depth()` is the gauge. Persistently non-zero while
  `wire_bytes_sent` stands still means the send side is stuck, not the server.

## In-flight bookkeeping: registered vs sent

`register_waiter` returns a `WaiterGuard` that removes its map entry on `Drop`, so an aborted caller can't leak one.
Before that, only the response deadline removed a waiter, which inflated the diagnostic and made `reserve_credits`'
"is anything outstanding?" starvation check permanently true.

- `Waiter` carries `registered_at` **and** `sent_at`. `OutstandingRequest::sent_age` is `None` while a request is still
  queued for the transport. ❌ Never read a large `age` as "the server didn't answer" without checking `sent_age`
  first — that conflation is what sent three investigations after an innocent server.
- The stale-request warning says which case it is, and reports the send-queue depth when a request isn't on the wire.
- Dropping a guard records the id in a bounded ring so a late response still counts as `responses_late_after_drop`
  rather than `responses_stray`; without it, routine cancellation would drown the "we got a frame we never asked for"
  signal.

## Response deadline

`Connection::await_response` gives up with `Error::Timeout` after 180 s of silence, so a server that stops answering on a live socket can't hang a caller. Tune or disable with `set_response_timeout`.

- The clock measures **silence, not elapsed time**: `Waiter.last_activity` is refreshed on every interim `STATUS_PENDING`, so an acknowledged long operation is never cut short.
- CHANGE_NOTIFY is exempt (`is_long_poll`) — it waits for an event that may never come. Add any new wait-for-an-event command there.
- Timing out removes the waiter, so an abandoned request leaves no entry in the routing map.

## Compound requests

`Connection::execute_compound(&[CompoundOp])` packs multiple operations into a single transport frame. Each sub-request is 8-byte aligned, linked via `NextCommand`. Subsequent related operations use `FileId::SENTINEL` (the server substitutes the real handle from the first CREATE).

- **Read compound**: CREATE + READ + CLOSE (3 ops, 1 round-trip). Default for `read_file`.
- **Write compound**: CREATE + WRITE + FLUSH + CLOSE (4 ops, 1 round-trip). Default for `write_file`.
- **Delete compound**: CREATE (DELETE_ON_CLOSE) + CLOSE (2 ops, 1 round-trip). Default for `delete_file` / `delete_directory`.
- **Rename compound**: CREATE + SET_INFO + CLOSE (3 ops, 1 round-trip). Default for `rename`.
- **Stat compound**: CREATE + QUERY_INFO (basic) + QUERY_INFO (standard) + CLOSE (4 ops, 1 round-trip). Default for `stat`.
- **Fs-info compound**: CREATE + QUERY_INFO (FileFsFullSizeInformation) + CLOSE (3 ops, 1 round-trip). Default for `fs_info`.
- If CREATE succeeds but a later op fails, the client issues a standalone CLOSE to avoid leaking the handle.

### Receiving compound responses

`execute_compound` returns `Result<Vec<Result<Frame>>>`. The outer `Result` is "did the compound hit the wire"; the inner one is per-sub-op (waiter-level: session expired, signature verify, connection dropped mid-await). Sub-op protocol status codes (`STATUS_OBJECT_NAME_NOT_FOUND` etc.) ride in the inner frame's `header.status`, not the inner `Result`. Per MS-SMB2 3.3.4.1.3 the server MAY split the compound response across multiple transport frames (Samba, QNAP, Windows Server in some cases); the receiver task routes each sub-response by `MessageId` so the per-waiter `oneshot::Receiver`s resolve independently and `execute_compound` reassembles the result vector in submission order.

Most callers use a small `all_or_first_err` helper (see `tree.rs`) that propagates the first inner `Err` as the outer `Err` (matching the pre-Phase-3 shortcircuit behavior) and hands back a `Vec<Frame>` indexable per sub-op. Tolerating partial failure (for example, CREATE ok, READ fails → issue standalone CLOSE with the create's returned `FileId`) keeps the individual inner `Result`s.

## Batch operations

`delete_files`, `rename_files`, and `stat_files` issue one `execute_compound` per file. Partial failures are independent — if 3 of 50 files fail, the other 47 still succeed. Each method returns `Vec<Result<T>>` in the same order as the input.

Decision/Why — sequential execute vs parallel: pre-Phase-3 these methods did "phase 1 send all compounds, phase 2 receive all" for wire-level pipelining. With the new API a caller can re-create that shape by spawning `tokio::spawn` tasks over `conn.clone()`s, each calling `execute_compound`. For cmdr's "delete 50 files" flows the sequential-compound cost is small (one round-trip per file) so we chose simplicity. If a workload needs the extra parallelism later, the refactor is local to each batch method.

## DFS (Distributed File System) resolution

Reactive DFS resolution with multi-target failover. When a convenience method gets `STATUS_PATH_NOT_COVERED` (mapped to `ErrorKind::DfsReferral`), it:

1. Calls `handle_dfs_redirect()` which resolves the referral via `DfsResolver` (cache or IOCTL)
2. Tries each target in the referral response (multi-target failover)
3. Creates a new connection + session for cross-server targets via `ensure_connection()`
4. Tree-connects to the target share via `ensure_tree()`
5. Updates the caller's `&mut Tree` in-place to point to the new server/share
6. Retries the operation with the resolved remaining path

**Key design decisions:**
- Convenience methods take `&mut Tree` (not `&Tree`) so DFS can update the tree in-place
- `disconnect_share` stays as `&Tree` (no redirect on teardown)
- Streaming methods (`download`, `upload`) keep `&Tree` because they return handles that borrow the tree for their lifetime
- `watch` now returns an *owned* `Watcher` (no lifetime); see the [Watcher pipelining](#watcher-pipelining) section
- Batch methods (`delete_files`, `rename_files`, `stat_files`) don't retry per-file; the caller should trigger one single-file operation first to resolve the redirect
- `dfs_enabled` flag on `ClientConfig` (default `true`) gates all DFS resolution
- Borrow checker requires inlining the connection lookup in `handle_dfs_redirect` to avoid double `&mut self` borrows

## Watcher pipelining

`Watcher` keeps **one CHANGE_NOTIFY request pre-issued on the wire at all times** after the first `next_events()` call. The wire never sits idle between responses. This closes the response→re-arm loss window that strict servers (older Samba builds, NAS firmware) drop events through.

Shape: `Watcher` owns a cloned `Connection` (cheap `Arc::clone`, all clones multiplex over the same SMB session) and a `Tree` clone — no lifetime parameter, no borrow against the caller's `Connection`. `next_events` dispatches the next request via `Connection::dispatch` (a sibling to `execute` that returns once `transport.send().await` completes, handing back the `oneshot::Receiver` for the response) *before* awaiting the previous response. So when control returns to the consumer, the server already has somewhere to put new events.

Decision/Why — eager-send `dispatch` vs `tokio::spawn(conn.execute(...))`: the spawn-based approach defers the send to when the spawned task is polled, which under tokio's `current_thread` scheduler may not happen until the spawning task yields. That left a gap where the simulator-modeled strict server dropped events. `dispatch` awaits transport.send() inline, so the eager-send guarantee is "after `.await` returns, the request is on the wire" — independent of scheduler.

Pinned by `client::watcher::loss_window_tests::watcher_does_not_lose_events_between_consecutive_requests`: a strict-server simulator drops events that arrive with no outstanding request. Pre-fix: 5/5 gap events dropped. Post-fix: 0/5 dropped.

## Pipelined I/O

For large files, `read_file_pipelined` / `write_file_pipelined` issue multiple `execute_with_credits` calls concurrently on cloned connections via `futures_util::stream::FuturesUnordered`. The sliding window stays at 32 in-flight requests; credits are not checked here (the connection's pool gates every send). Chunk size is `min(512 KB, max_read_size)`. This is the core performance feature -- without it, throughput is ~10x worse.

`FileWriter` owns its `Connection` (cheap `Arc::clone`) and `Arc<Tree>` — no lifetime parameter, no borrow against the `SmbClient` that built it. It keeps an owned `FuturesUnordered<BoxedWriteFut>` field — `launch_wire_chunk` pushes a boxed `execute_with_credits` future, `drain_one` awaits `in_flight.next()`, and the public `write_chunk` / `finish` / `abort` drive that state machine.

FileWriter provides push-based pipelined writes. The consumer pushes chunks at their own pace via `write_chunk`, with the sliding window handling backpressure. Complement to FileDownload (read streaming). Build one via `open_file_writer(tree, conn, path)` (free function), `Tree::create_file_writer(&Arc<Self>, conn, path)`, or `SmbClient::create_file_writer(&self, tree, path)` — the last clones the client's primary connection internally for convenience.

## Random-access reads (`FileReader`)

`FileReader` (in `stream.rs`) holds ONE open handle and serves any number of *positioned* reads (`read_at(offset, len)`, the SMB analog of `pread`) before an explicit `close()`. It's the primitive for a consumer that parses a file's structure by jumping around it (zip central-directory browse + entry extract), where reopening per read would leak a handle each time. Build one via `open_file_reader(tree: Arc<Tree>, conn, path)` (free fn), `Tree::open_file_reader(&Arc<Self>, conn, path)`, or `SmbClient::open_file_reader(&self, tree, path)` (clones the primary connection).

Same owned-`Connection` + `Arc<Tree>` shape as `FileWriter`, so it's `'static`. `read_at` takes `&self` (no shared cursor) and issues `execute_with_credits` READs, splitting a range larger than `MaxReadSize` into consecutive wire reads and reassembling. It clamps to the size seen at open, so a read at/after EOF returns empty and a straddling read is short — never an error. `close()` consumes `self` (read-after-close is a compile error); like the other stream handles, `Drop` can't CLOSE (no async drop) and only logs a debug warning, so a dropped-without-close reader leaks the handle until session teardown. Pinned by the `stream.rs` `file_reader_*` mock tests (one CREATE, N READs, one CLOSE; EOF clamping; range splitting; drop-sends-no-close) and the `guest_file_reader_positioned_reads` Docker test.

## Server-side copy (`copy.rs`)

`FSCTL_SRV_COPYCHUNK` copies byte ranges between two files *on the server* — the data never crosses the wire. Two tiers, both on `Tree` (with `SmbClient` wrappers that route via `connection_for_tree`):

- **Convenience**: `server_side_copy_file` (whole file, truncating dest) and `server_side_copy_file_range` (a range at a chosen dest offset, non-truncating dest). Both open source (read) + dest (read+write), get a resume key, batch the copy, flush+close both, and never leak a handle on an error path (shared `copy_paths` helper).
- **Primitives**: `request_resume_key` (source handle → opaque `ResumeKey`), `copy_chunks` (one IOCTL against an open read+write dest), and `server_side_copy_range` (batches over open handles). These take caller-held `FileId`s like `open_file` does; `open_file_readwrite` opens a dest and `close_handle` (now public) releases it.

Gotchas / why:
- **Dest needs read+write.** `FSCTL_SRV_COPYCHUNK` requires the destination open to carry `FILE_READ_DATA` *and* `FILE_WRITE_DATA` (MS-SMB2 3.3.5.15.6). The read+write opens grant both; a plain write handle would get `ACCESS_DENIED`.
- **Limits negotiation is a normal path, not an error.** When a request exceeds the server's per-request limits it returns `STATUS_INVALID_PARAMETER` *with* a 12-byte `SRV_COPYCHUNK_RESPONSE` carrying the limits (MS-SMB2 3.2.5.14.3). `copy_chunks` surfaces that as `Ok(CopyChunkOutcome::Rejected { limits })`, not `Err`; `server_side_copy_range` starts at `ServerSideCopyLimits::CONSERVATIVE` (16×1 MiB / 16 MiB, the common Windows/Samba minimum) and re-batches within advertised limits, guarding against an infinite loop via "advertised == current → error".
- **Unsupported servers are typed.** Old Samba / NAS firmware without copychunk return `STATUS_NOT_SUPPORTED` / `STATUS_INVALID_DEVICE_REQUEST`, classified `ErrorKind::Unsupported`. Consumers branch on it to fall back to read-then-write — no string matching.
- **Positioned append pairs with it.** `create_file_writer_at(path, offset)` opens non-truncating (`FileOpenIf`) and seeds the writer's offset, so a consumer can server-side-copy a retained prefix into a temp, then append (the archive tail-rewrite shape).

Full behavioral detail lives in the `copy.rs` module rustdoc.

## Streaming download entry points

Two symmetric ways to start a `FileDownload`:

- `SmbClient::download(&mut self, &Tree, path)` — convenience wrapper that borrows the client's internal `Connection`.
- `Tree::download(&self, &mut Connection, path)` — takes the `Connection` directly. Use this when you hold a
  `conn.clone()` and want to drive concurrent downloads on the same SMB session (each clone pairs with one outstanding
  download; the receiver task multiplexes responses by `MessageId`). `SmbClient::download` delegates here.

For full control, `Tree::open_file` (returns `(FileId, u64)`) plus `FileDownload::new` let callers build custom chunk
loops with non-default `chunk_size`. Most users shouldn't need this — `read_file_compound` (1 RTT) handles small files
and `Tree::download` / `SmbClient::download` handle the streaming case.

FileWriter has two terminal operations:
- `finish()` — send all buffered data, drain in-flight WRITEs, FLUSH (fsync on the server), CLOSE. Use on normal completion.
- `abort()` — discard unsent data, drain in-flight WRITEs to keep credits/message-ids in sync, skip FLUSH, best-effort CLOSE. Use on cancellation or error paths where the partial remote file is going to be deleted anyway — `abort()` saves the fsync round-trip. The caller is responsible for deleting the partial remote file.

Both consume `self` so write-after-close/abort is a compile error. `Drop` logs a debug warning if neither was called (handle leaks).

## Session setup flow

1. Send NTLM NEGOTIATE in SESSION_SETUP
2. Receive STATUS_MORE_PROCESSING_REQUIRED with challenge, update preauth hash
3. Send NTLM AUTHENTICATE in SESSION_SETUP, update preauth hash with request only
4. Receive STATUS_SUCCESS (do NOT include in preauth hash)
5. Derive signing/encryption keys via SP800-108 KDF
6. Activate signing on the connection
7. If session or share requires encryption, activate encryption (TRANSFORM_HEADER wrapping with AEAD)

## Encryption

Encryption is activated when the session flags include `ENCRYPT_DATA` or a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`. When active:
- Outgoing messages are wrapped in TRANSFORM_HEADER (protocol ID 0xFD) with a monotonic nonce
- Incoming messages with 0xFD are decrypted before processing
- Signing is skipped (AEAD provides authentication)
- Compound chains are encrypted as one unit (pitfall #9)

Tree-level encryption: `connect_share()` checks the share's encrypt flag and activates encryption on the connection if needed, even if the session didn't require it.

## Reconnection

`SmbClient::reconnect()` creates a fresh TCP connection, re-negotiates, and re-authenticates using stored credentials. All previous `Tree` handles and `FileId` values are invalidated. The caller must `connect_share` again.

## Connection internals: receiver task + `oneshot` routing

`Connection::execute` / `execute_compound` is the primary API. A background receiver task (spawned per `Connection` at `from_transport`) owns the transport's read half and routes each sub-frame to a per-request `oneshot::Sender` by `MessageId`.

- `Connection` is `Clone` and holds just `Arc<Inner>`. `Inner` owns `waiters: Mutex<HashMap<MessageId, Waiter>>`, `credits: CreditPool`, `next_message_id: AtomicU64`, the transport send half (via `Arc<dyn TransportSend>`), the receiver task's `JoinHandle`, and crypto state. All state is behind atomics or short-critical-section `std::sync::Mutex`.
- `execute(command, body, tree_id)` allocates a `MessageId` (`AtomicU64::fetch_add(credit_charge)`), registers a `oneshot::Sender` in `waiters` atomically under the waiters lock (re-checks `disconnected` there to rule out a TOCTOU where the receiver task has already shut down and drained the map), packs the frame, signs/encrypts/compresses as needed, and writes through `TransportSend::send`. Then it awaits the local `oneshot::Receiver`. Returns `Result<Frame { header, body, raw }>`.
- `execute_compound(&[CompoundOp])` does the same per sub-op, building one compound transport frame with `NextCommand` offsets, then awaits each per-sub-op receiver sequentially. Each receiver resolves independently (the receiver task splits the server's response by `NextCommand` and routes each sub-response by its `MessageId`). The outer `Result` is "did the compound hit the wire"; the inner `Vec<Result<Frame>>` has one entry per sub-op.
- **Cancellation-by-drop is safe by construction.** If a caller's future is aborted (`tokio::spawn` + `JoinHandle::abort()` is the common path in consumers), the locally-owned `oneshot::Receiver` drops; the receiver task's `Sender::send` then fails silently when the late frame arrives; the frame is discarded. Credit grants are still banked in the receiver task so dropped-caller frames don't starve throughput.
- **Transport drop** fans `Err(Disconnected)` to every pending `oneshot::Sender` and sets `disconnected=true` under the waiters lock. Subsequent `execute` / `execute_compound` sees `disconnected=true` and returns `Err(Disconnected)` without inserting (no leaked waiters).

Gotcha/Why — pre-Phase-3 `send_request` / `receive_response` split API was removed in Phase 3 Stage A.3. The test-mode `set_orphan_filter_enabled(false)` escape hatch is gone too; tests that build mocks without going through `setup_connection` call `mock.enable_auto_rewrite_msg_id()` instead, which rewrites each queued response's zero-msg_id to match the next pending sent msg_id in FIFO order.

Full design in [docs/specs/connection-actor.md](../../docs/specs/connection-actor.md).

## Key decisions

- **Owned `FileWriter`: N concurrent streamed writes over one Connection without external locking**: `FileWriter` owns its `Connection` (cheap `Arc::clone`) and `Arc<Tree>` instead of borrowing `&'a mut Connection` from the `SmbClient`. Built via the free `open_file_writer(tree: Arc<Tree>, conn: Connection, path: &str)` or one of the two convenience wrappers (`Tree::create_file_writer`, `SmbClient::create_file_writer`). Multiple writers built from clones of the same `Connection` pipeline their WRITEs over one SMB session — the receiver task multiplexes responses by `MessageId`. The borrowed variant was the root cause of a production-reproducing deadlock in the cmdr SMB volume's `write_from_stream` (Phase C QNAP test, 200 × 7 MB concurrent overwrites): the consumer had to hold its session mutex for the entire upload because the writer borrowed `&'a mut Connection`. Owning the connection removes the lock from the hot path entirely.
- **`execute` / `execute_compound` take `&self`**: `Connection: Clone` supports concurrent ops per connection — clone freely across tasks, the receiver task multiplexes responses by `MessageId`. `Tree::*` methods still take `&mut Connection` because session-setup mutators (`activate_signing`, `set_session_id`) keep `&mut self`; Tree code calls both, so `&mut` at that layer is the least-churn choice.
- **Sender work stays on the caller thread, only the receiver is a task**: The send path already uses an internal Mutex on the transport write half for ordering; adding a second task just to drive sends would add latency without correctness gain. The receiver bug (orphan/dropped-caller frames corrupting the wire) only existed on the receive side, so only the receive side needed a task.
- **Compound reads as default**: One round-trip for small files. Saves 2 RTTs vs sequential CREATE/READ/CLOSE.
- **512 KB pipeline chunks**: Balances between too many small requests (overhead) and too few large ones (credit starvation). Gives ~20 chunks per 10 MB file.
- **Password stored in `SmbClient`**: Enables reconnect without re-prompting. Not encrypted in memory. Drop when done.

## Gotchas

- **Preauth hash excludes the final success response**: Only STATUS_MORE_PROCESSING_REQUIRED responses are hashed. Including the success response produces wrong keys. (MS-SMB2 3.2.5.3.1)
- **Oplock break notifications arrive with MessageId 0xFFFFFFFFFFFFFFFF**: The receiver task detects these and skips them without invoking a waiter lookup.
- **Register-waiter must be atomic with `disconnected` check**: The waiters lock covers both reading `disconnected` and inserting the `oneshot::Sender`. If the check and insert were racy, a receiver-task failure mid-send could leave an orphan `Sender` in the map that never gets routed — caller would hang on `rx.await` forever. Same goes for `fan_error_to_waiters`: it sets `disconnected=true` UNDER the same waiters lock before draining, so new sends strictly either succeed-and-get-drained or fail at the insert check.
- **Unrecoverable frame errors tear down the connection** (Phase 3 P3.4): decrypt failure, decompress failure, or a malformed sub-frame header that survives `split_compound` all cause the receiver task to call `fan_error_to_waiters(Err(Disconnected))` and exit. The alternative — log-and-continue — would leave the matching waiter hanging forever, because the msg_id isn't recoverable from an unparseable frame. The connection is also out of sync after one bad frame, so reconnect is the right move anyway. Counted via `MetricsSnapshot::{decrypt_failures, decompress_failures, malformed_frames}`.
- **STATUS_PENDING loop**: CHANGE_NOTIFY and other long-poll operations get STATUS_PENDING first. The receiver task keeps the waiter registered on PENDING and does NOT forward the interim response. Credits from PENDING are still banked, and the waiter's `last_activity` is refreshed so the response deadline restarts. Counted via `MetricsSnapshot::status_pending_loops`.
- **Signing and encryption are mutually exclusive on the wire**: When encrypting, zero the signature field (AEAD provides integrity). On receive, skip signature verification if decryption succeeded.
- **Compound encryption wraps the entire chain**: One TRANSFORM_HEADER for all sub-requests concatenated, not per sub-request.
- **Share-level encryption**: If a share has `SMB2_SHAREFLAG_ENCRYPT_DATA`, encryption is activated even if the session didn't require it.
- **FileDownload/FileUpload can leak handles on drop**: Rust has no async drop. If not consumed fully, the file handle leaks. The types log a warning.
- **FileWriter can leak handles on drop**: Same as FileDownload/FileUpload. Rust has no async drop. If not consumed via `finish()` or `abort()`, the file handle leaks. The type logs a debug warning.
- **DFS paths must include server\share prefix**: When `SMB2_FLAGS_DFS_OPERATIONS` is set, the server expects the path to start with `server\share\` (MS-SMB2 3.2.4.3). `Tree::format_path()` handles this automatically for DFS shares. Without the prefix, Samba strips the first two path components, leading to wrong file opens.
- **DFS redirect changes the tree in-place**: After a DFS redirect, `tree.server`, `tree.share_name`, and `tree.tree_id` all change. Subsequent operations on the same tree use the target server directly -- they must use target-relative paths, not the original DFS paths.
- **tree.server stores addr:port**: The `server` field on `Tree` stores the full `addr:port` string (not just hostname) so `connection_for_tree` can distinguish servers that share the same hostname but use different ports.
- **Servers MAY split compound responses**: MS-SMB2 section 3.3.4.1.3 says the server SHOULD compound responses but is not required to. Samba (and QNAP firmware built on it) is known to split compound chains into separate frames in some scenarios; Windows Server does too under certain conditions. Compound-using methods (`read_file_compound`, `write_file_compound`, `fs_info`, `stat`, `rename`, `delete_file`, batch `*_files`) call `Connection::receive_compound_expected(n)` instead of `receive_compound()`, which transparently gathers additional frames if the server splits. Logged at DEBUG, not WARN -- it's a spec edge case, not a problem.
