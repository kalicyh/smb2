//! Fault injection: hostile-but-plausible servers.
//!
//! This class of bug survived a year of testing because nothing ever simulated
//! a server that stays connected and stops cooperating. Every failure here is
//! one that has actually been observed against real hardware — a QNAP TS-464
//! that answered nothing while TCP stayed `ESTABLISHED`, a macOS laptop
//! roaming between access points mid-copy — and none of them are reachable
//! from a mock that only replays a canned conversation.
//!
//! **Every wait in this file is bounded and panics on expiry.** A test that
//! can hang is worse than no test: it turns a red build into a wedged one, and
//! the failure this module exists to catch is a hang.
//!
//! The shared shape is [`ScriptedServer`]: a transport whose send half always
//! succeeds (the way a kernel socket buffer does after the peer has vanished)
//! and whose receive half answers according to a policy the test can change
//! mid-flight. Nothing in it ever returns an error or EOF, so a client that
//! only notices dead connections by reading one will wait forever — which is
//! precisely the bug.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;

use crate::client::connection::{pack_message, Connection};
use crate::error::{Error, Result};
use crate::msg::echo::EchoResponse;
use crate::msg::header::Header;
use crate::msg::write::{WriteRequest, WriteResponse};
use crate::pack::{ReadCursor, Unpack};
use crate::transport::{TransportReceive, TransportSend};
use crate::types::status::NtStatus;
use crate::types::{Command, MessageId, TreeId};

// ── Timings ────────────────────────────────────────────────────────────────
//
// Scaled-down versions of the shipping defaults, keeping the same ratios so a
// test proves something about the real configuration rather than about a shape
// that only exists in tests. The keepalive reaches a verdict inside the
// response deadline, exactly as the defaults do.

/// Server silence that triggers a probe. Real default: 5 s.
const KEEPALIVE: Duration = Duration::from_millis(200);
/// Silence budget for one request. Real default: 30 s.
const BASE_DEADLINE: Duration = Duration::from_millis(500);
/// Outer bound on any single test. Generously above every deadline above, so
/// tripping it means something genuinely hung rather than ran slowly on a
/// loaded machine.
const TEST_BUDGET: Duration = Duration::from_secs(20);

// ── The scripted server ────────────────────────────────────────────────────

/// What the server does with each request it receives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Answer {
    /// Answer everything promptly. A healthy server.
    Everything,
    /// Answer ECHO and nothing else.
    ///
    /// The whole reason the keepalive exists: the server is unmistakably
    /// alive and processing requests, while one operation is taking far
    /// longer than any fixed deadline would allow. A loaded spinning-disk NAS
    /// mid-write looks exactly like this, and killing it is the failure mode
    /// an aggressive deadline buys you if it cannot tell slow from dead.
    EchoOnly,
    /// Answer ECHO with `STATUS_NETWORK_SESSION_EXPIRED` and nothing else.
    ///
    /// A bad answer is still an answer: the server put a frame on the wire, so
    /// it is unmistakably processing requests, which is the only question the
    /// probe asks. A consumer re-running `Session::setup` on this connection
    /// must not be left with a keepalive that quietly retired.
    EchoExpired,
    /// Answer nothing at all, while the socket keeps accepting writes.
    ///
    /// Covers every cause at once — NAS reboot, share offline, disk stall,
    /// Wi-Fi roam with no RST — because from the client's side they are one
    /// state, and detection that depends on knowing which is not detection.
    Nothing,
}

/// A transport that lets a test decide, per moment, what the server does.
struct ScriptedServer {
    /// Responses ready for the client to read.
    outbox: Mutex<VecDeque<Vec<u8>>>,
    ready: Notify,
    answer: Mutex<Answer>,
    /// Requests seen, in order, and whether they have been answered.
    seen: Mutex<Vec<(Command, MessageId, bool)>>,
    echoes: AtomicUsize,
}

impl ScriptedServer {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            outbox: Mutex::new(VecDeque::new()),
            ready: Notify::new(),
            answer: Mutex::new(answer),
            seen: Mutex::new(Vec::new()),
            echoes: AtomicUsize::new(0),
        })
    }

    fn set_answer(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }

    fn echo_count(&self) -> usize {
        self.echoes.load(Ordering::Relaxed)
    }

    /// Answer every request seen so far that has not been answered yet.
    ///
    /// The "the server was busy, not dead, and here is your data" path.
    fn answer_everything_outstanding(&self) {
        let pending: Vec<(Command, MessageId)> = {
            let mut seen = self.seen.lock().unwrap();
            seen.iter_mut()
                .filter(|(_, _, answered)| !*answered)
                .map(|entry| {
                    entry.2 = true;
                    (entry.0, entry.1)
                })
                .collect()
        };
        for (command, msg_id) in pending {
            if let Some(frame) = build_response(command, msg_id) {
                self.push(frame);
            }
        }
    }

    /// Send an interim `STATUS_PENDING` for `msg_id`: "still working on it".
    ///
    /// A sign of life that is not an answer, which is the third state the
    /// deadline has to cope with alongside "answered" and "silent".
    fn push_pending(&self, command: Command, msg_id: MessageId) {
        let mut h = Header::new_request(command);
        h.flags.set_response();
        h.message_id = msg_id;
        h.credits = 8;
        h.status = NtStatus::PENDING;
        self.push(pack_message(&h, &EchoResponse));
    }

    fn push(&self, frame: Vec<u8>) {
        self.outbox.lock().unwrap().push_back(frame);
        self.ready.notify_one();
    }

    /// The `MessageId` of the first request of this command, waiting (bounded)
    /// for it to arrive.
    async fn wait_for_request(&self, command: Command) -> MessageId {
        let deadline = Instant::now() + TEST_BUDGET;
        loop {
            if let Some((_, id, _)) = self
                .seen
                .lock()
                .unwrap()
                .iter()
                .find(|(c, _, _)| *c == command)
            {
                return *id;
            }
            assert!(
                Instant::now() < deadline,
                "the client never sent a {command:?} request"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
}

#[async_trait]
impl TransportSend for ScriptedServer {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // Always succeeds. A socket whose peer has vanished keeps accepting
        // writes until the kernel buffer fills, which is why the send side
        // cannot be the thing that notices.
        let mut cursor = ReadCursor::new(data);
        let Ok(header) = Header::unpack(&mut cursor) else {
            return Ok(()); // not an SMB2 frame; nothing to script
        };
        let answer = *self.answer.lock().unwrap();
        let is_echo = header.command == Command::Echo;
        if is_echo {
            self.echoes.fetch_add(1, Ordering::Relaxed);
        }
        let will_answer = match answer {
            Answer::Everything => true,
            Answer::EchoOnly | Answer::EchoExpired => is_echo,
            Answer::Nothing => false,
        };
        self.seen
            .lock()
            .unwrap()
            .push((header.command, header.message_id, will_answer));
        if will_answer {
            let frame = if answer == Answer::EchoExpired && is_echo {
                Some(build_expired_response(header.message_id))
            } else {
                build_response(header.command, header.message_id)
            };
            if let Some(frame) = frame {
                self.push(frame);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl TransportReceive for ScriptedServer {
    async fn receive(&self) -> Result<Vec<u8>> {
        loop {
            let queued = self.outbox.lock().unwrap().pop_front();
            match queued {
                Some(frame) => return Ok(frame),
                // Never `Err`, never EOF. The receive half of a black-holed
                // link parks forever, and a client that relies on this
                // returning to notice trouble never notices.
                None => self.ready.notified().await,
            }
        }
    }
}

/// Build the server's answer to `command`, or `None` for a command this
/// harness has no canned reply for.
fn build_response(command: Command, msg_id: MessageId) -> Option<Vec<u8>> {
    let mut h = Header::new_request(command);
    h.flags.set_response();
    h.message_id = msg_id;
    // Generous, so nothing in these tests is accidentally credit-bound —
    // credit starvation has its own tests and is not what is under test here.
    h.credits = 8;
    match command {
        Command::Echo => Some(pack_message(&h, &EchoResponse)),
        Command::Write => Some(pack_message(
            &h,
            &WriteResponse {
                count: 4,
                remaining: 0,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
            },
        )),
        _ => None,
    }
}

/// An ECHO answered with `STATUS_NETWORK_SESSION_EXPIRED`.
fn build_expired_response(msg_id: MessageId) -> Vec<u8> {
    let mut h = Header::new_request(Command::Echo);
    h.flags.set_response();
    h.message_id = msg_id;
    h.credits = 8;
    h.status = NtStatus::NETWORK_SESSION_EXPIRED;
    pack_message(
        &h,
        &crate::msg::header::ErrorResponse {
            error_context_count: 0,
            error_data: vec![],
        },
    )
}

// ── Harness ────────────────────────────────────────────────────────────────

/// A connection wired to `server`, tuned to the scaled-down timings above.
fn connect(server: &Arc<ScriptedServer>) -> Connection {
    let conn = Connection::from_transport(
        Box::new(Arc::clone(server)),
        Box::new(Arc::clone(server)),
        "scripted-server",
    );
    conn.set_credits(512);
    conn.set_response_timeout(Some(BASE_DEADLINE));
    conn.set_keepalive(Some(KEEPALIVE));
    conn
}

/// A WRITE body. The command matters (ECHO is what the keepalive sends, so
/// using it for the payload request would make the two indistinguishable);
/// the bytes do not.
fn a_write() -> WriteRequest {
    WriteRequest {
        data_offset: 0x70,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        offset: 0,
        file_id: crate::types::FileId {
            persistent: 1,
            volatile: 2,
        },
        channel: 0,
        remaining_bytes: 0,
        flags: 0,
        data: vec![0xAB; 4],
    }
}

/// Issue a WRITE on its own task, so the test can observe the connection while
/// it is outstanding.
fn spawn_write(conn: &Connection) -> tokio::task::JoinHandle<Result<crate::client::Frame>> {
    let c = conn.clone();
    tokio::spawn(async move { c.execute(Command::Write, &a_write(), Some(TreeId(1))).await })
}

/// Poll until `cond` holds, panicking rather than hanging if it never does.
///
/// Every timing assertion in this file is one-sided on purpose. A loaded
/// machine can only ever make things take LONGER, so "wait for X, bounded" is
/// stable where "sleep N, then assert X" is a coin flip — and a flaky test
/// about hangs is worth less than no test at all.
async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + TEST_BUDGET;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Await a task, panicking rather than hanging if it never resolves.
async fn finish<T>(task: tokio::task::JoinHandle<T>, what: &str) -> T {
    tokio::time::timeout(TEST_BUDGET, task)
        .await
        .unwrap_or_else(|_| panic!("{what} never resolved -- it hung, which is the bug"))
        .expect("task panicked")
}

// ── The tests ──────────────────────────────────────────────────────────────

/// The point of the whole exercise: a request the server has not answered, on
/// a connection the server is demonstrably still running, must not be killed
/// by the deadline that exists for dead connections.
///
/// Without the ECHO probe the client has one number to work with and no way to
/// tell these two servers apart, so it has to choose: short enough to catch
/// the dead one and it murders this one, long enough to spare this one and the
/// dead one freezes a transfer for minutes.
#[tokio::test]
async fn a_slow_write_outlives_the_deadline_while_echo_proves_the_server_alive() {
    let server = ScriptedServer::new(Answer::EchoOnly);
    let conn = connect(&server);

    let started = Instant::now();
    // Bounded, not forgiving: alive is a reason for more patience, not for
    // unlimited patience. A server that answers ECHO but never this request is
    // stalled in a way waiting cannot fix, so the ceiling still ends it.
    let outcome = finish(spawn_write(&conn), "the write").await;
    let took = started.elapsed();

    assert!(
        matches!(outcome, Err(Error::Timeout)),
        "expected the ceiling to fire with a typed timeout, got {outcome:?}"
    );
    assert_eq!(
        conn.metrics().response_deadline_extensions,
        1,
        "the write should have been granted the extension exactly once (once per \
         request, not once per tick); it took {took:?}"
    );
    assert!(
        took >= BASE_DEADLINE * 2,
        "the write was cut off after {took:?}, near the plain deadline of \
         {BASE_DEADLINE:?} — the answered ECHOes should have bought it far more room"
    );
    assert!(
        server.echo_count() >= 2,
        "the extension has to rest on probes, saw {} ECHO(es)",
        server.echo_count()
    );
    assert_eq!(conn.metrics().response_timeouts, 1);
}

/// The happy ending of the same story: the server was busy, not broken, and
/// the write completes.
///
/// Pre-keepalive this write was cut off at the base deadline and the transfer
/// failed, for no reason other than that the client could not tell.
#[tokio::test]
async fn a_write_the_server_was_merely_slow_about_completes_successfully() {
    let server = ScriptedServer::new(Answer::EchoOnly);
    let conn = connect(&server);
    // Room to spare above the base deadline, so the ceiling is nowhere near
    // and only the extension can explain the write surviving.
    conn.set_response_timeout(Some(BASE_DEADLINE * 4));

    let write = spawn_write(&conn);
    let msg_id = server.wait_for_request(Command::Write).await;

    // Wait for the write to actually outlive its plain deadline, then let the
    // data land.
    let metrics = conn.clone();
    wait_until("the write to outlive its plain deadline", || {
        metrics.metrics().response_deadline_extensions == 1
    })
    .await;
    assert!(!write.is_finished(), "cut off while the server was alive");
    server.set_answer(Answer::Everything);
    server.answer_everything_outstanding();

    let outcome = finish(write, "the write").await;
    assert!(
        outcome.is_ok(),
        "the server answered; the write must succeed, got {outcome:?}"
    );
    assert_eq!(
        conn.metrics().response_timeouts,
        0,
        "nothing was abandoned: msg_id={} came back",
        msg_id.0
    );
}

/// A server that dies mid-transfer, the way a NAS reboot or a share going
/// offline looks: it was answering, and then it is not, and the socket never
/// says a word about it.
///
/// The response deadline is set far out on purpose — passing this test means
/// the keepalive reached the verdict, not that the deadline eventually did.
#[tokio::test]
async fn a_server_that_dies_mid_transfer_is_declared_dead_and_every_waiter_told() {
    let server = ScriptedServer::new(Answer::Everything);
    let conn = connect(&server);
    conn.set_response_timeout(Some(Duration::from_secs(30)));

    // A healthy exchange first, so the connection has real proof of life to
    // lose. Detection has to survive the transition, not just the cold case.
    let warmup = spawn_write(&conn);
    assert!(finish(warmup, "the warm-up write").await.is_ok());

    server.set_answer(Answer::Nothing);
    let first = spawn_write(&conn);
    let second = spawn_write(&conn);

    let first = finish(first, "the first write").await;
    let second = finish(second, "the second write").await;
    for (which, outcome) in [("first", first), ("second", second)] {
        assert!(
            matches!(outcome, Err(Error::ServerUnresponsive { probes: 2, .. })),
            "the {which} write should name the dead session, got {outcome:?}"
        );
    }
    assert!(
        conn.metrics().keepalive_failures >= 2,
        "two unanswered probes are what justify the verdict"
    );
    assert!(
        conn.diagnostics().disconnected,
        "a session declared dead must be marked dead, so nothing new parks on it"
    );
}

/// The Wi-Fi-roam / laptop-sleep case: TCP goes to a black hole with no RST,
/// no FIN, and no error. Routine on macOS, and indistinguishable from a dead
/// server — which is the point, because the client should not need to
/// distinguish them.
///
/// The extra thing this pins beyond the test above: once the verdict is in,
/// **new** work fails immediately instead of parking on a corpse. A detector
/// that only rescues the requests that happened to be in flight would let the
/// next one hang all over again.
#[tokio::test]
async fn a_link_that_goes_black_without_a_reset_fails_current_and_future_requests() {
    let server = ScriptedServer::new(Answer::Everything);
    let conn = connect(&server);
    conn.set_response_timeout(Some(Duration::from_secs(30)));

    let warmup = spawn_write(&conn);
    assert!(finish(warmup, "the warm-up write").await.is_ok());

    server.set_answer(Answer::Nothing); // the access point changed underneath us
    let stranded = finish(spawn_write(&conn), "the stranded write").await;
    assert!(
        matches!(stranded, Err(Error::ServerUnresponsive { .. })),
        "expected the session to be declared dead, got {stranded:?}"
    );

    let afterwards = tokio::time::timeout(
        TEST_BUDGET,
        conn.execute(Command::Write, &a_write(), Some(TreeId(1))),
    )
    .await
    .expect("a request on a connection already known to be dead must fail at once, not park");
    assert!(
        matches!(afterwards, Err(Error::Disconnected)),
        "expected an immediate rejection, got {afterwards:?}"
    );
}

/// A connection with nothing on the wire is not probed.
///
/// There is no work to protect, so the probe would buy nothing and cost a
/// round trip; the next request brings its own deadlines with it. Consumers
/// hold idle connections open for a long time (a file manager with a mounted
/// share and nobody looking at it), and background chatter on all of them is a
/// real cost.
#[tokio::test]
async fn an_idle_connection_is_never_probed() {
    let server = ScriptedServer::new(Answer::Everything);
    let conn = connect(&server);

    tokio::time::sleep(KEEPALIVE * 8).await;

    assert_eq!(
        server.echo_count(),
        0,
        "an idle connection has nothing to keep alive"
    );
    assert_eq!(conn.metrics().keepalive_probes_sent, 0);
}

/// A server saying `STATUS_PENDING` is a server talking. The keepalive
/// measures silence, so it stays quiet, and the deadline never fires.
///
/// This is what keeps the feature free on a busy connection: a transfer at
/// full pipeline depth has frames arriving constantly, so it never probes at
/// all.
#[tokio::test]
async fn a_server_that_keeps_saying_it_is_working_is_never_probed() {
    let server = ScriptedServer::new(Answer::EchoOnly);
    let conn = connect(&server);

    let write = spawn_write(&conn);
    let msg_id = server.wait_for_request(Command::Write).await;

    // "Still working on it" eight times more often than the probe threshold,
    // for well past the base deadline. The wide margin is deliberate: a
    // loaded machine overshooting one sleep must not be able to look like a
    // quiet wire.
    for _ in 0..40 {
        tokio::time::sleep(KEEPALIVE / 8).await;
        server.push_pending(Command::Write, msg_id);
    }
    assert!(!write.is_finished(), "an acknowledged request was cut off");
    assert_eq!(
        server.echo_count(),
        0,
        "the wire was never quiet, so there was nothing to probe about"
    );
    assert_eq!(
        conn.metrics().response_deadline_extensions,
        0,
        "STATUS_PENDING restarts the deadline outright; no extension is needed"
    );

    server.set_answer(Answer::Everything);
    server.answer_everything_outstanding();
    assert!(finish(write, "the write").await.is_ok());
}

/// A probe that cannot be sent is evidence of nothing, and must never be
/// counted as a death.
///
/// The trap this guards: the credit window is fully spent exactly when the
/// pipeline is deepest, which is exactly when a server goes quiet under load.
/// Treating "I could not ask" as "it did not answer" would turn the busiest
/// healthy transfers into the ones most likely to be torn down — the
/// starvation hang from the client side, wearing a different hat.
#[tokio::test]
async fn a_probe_that_cannot_get_a_credit_is_skipped_rather_than_called_a_death() {
    let server = ScriptedServer::new(Answer::Nothing);
    let conn = connect(&server);
    // Exactly enough for the write and nothing left over, and no response will
    // ever bring a credit back.
    conn.set_credits(1);
    conn.set_response_timeout(Some(BASE_DEADLINE * 8));

    let write = spawn_write(&conn);
    let metrics = conn.clone();
    wait_until("a probe round to be skipped for want of a credit", || {
        metrics.metrics().keepalive_probes_skipped >= 1
    })
    .await;
    assert_eq!(
        conn.metrics().keepalive_failures,
        0,
        "a probe that was never sent cannot have gone unanswered"
    );

    let outcome = finish(write, "the write").await;
    assert!(
        matches!(outcome, Err(Error::Timeout)),
        "with no probe possible the plain response deadline is what should fire, got {outcome:?}"
    );
    assert_eq!(
        server.echo_count(),
        0,
        "there was no credit to send an ECHO with"
    );
    assert_eq!(
        conn.metrics().keepalive_failures,
        0,
        "a connection that could never be probed must never be declared dead"
    );
    assert!(
        !conn.diagnostics().disconnected,
        "the keepalive tore down a connection it never managed to ask a question"
    );
}

/// The extension is granted on evidence, never on assumption.
///
/// With the keepalive off nothing refreshes the liveness clock, so a recent
/// frame is luck rather than proof — and a deadline extended on luck is the
/// hang coming back through the front door.
#[tokio::test]
async fn a_request_with_no_liveness_evidence_gets_the_plain_deadline() {
    let server = ScriptedServer::new(Answer::Everything);
    let conn = connect(&server);
    conn.set_keepalive(None);

    // A healthy exchange, so the liveness clock is as fresh as it ever gets.
    assert!(finish(spawn_write(&conn), "the warm-up write")
        .await
        .is_ok());

    server.set_answer(Answer::Nothing);
    let outcome = finish(spawn_write(&conn), "the write").await;

    assert!(
        matches!(outcome, Err(Error::Timeout)),
        "expected the plain deadline, got {outcome:?}"
    );
    assert_eq!(
        conn.metrics().response_deadline_extensions,
        0,
        "the deadline was extended with no probe to justify it"
    );
    assert_eq!(
        server.echo_count(),
        0,
        "the keepalive was turned off and must stay off"
    );
}

/// The one wait the response deadline cannot protect: a long-poll
/// CHANGE_NOTIFY, which is exempt by design because it waits for an event that
/// may never come.
///
/// A `Watcher` holds one open on the wire at all times, so before the
/// keepalive a dead server left it waiting for an event that could never
/// arrive — for hours, silently, with the connection looking idle rather than
/// broken. Probing is what closes that, and it is the reason long-poll
/// commands are deliberately NOT exempt from the keepalive the way they are
/// from the deadline.
#[tokio::test]
async fn a_long_poll_waiting_on_a_dead_server_is_told_instead_of_waiting_forever() {
    let server = ScriptedServer::new(Answer::Nothing);
    let conn = connect(&server);
    // Off entirely: if this test passes, nothing but the keepalive could have
    // made it pass, since CHANGE_NOTIFY ignores the deadline at any setting.
    conn.set_response_timeout(None);

    let watching = {
        let c = conn.clone();
        tokio::spawn(async move {
            let req = crate::msg::change_notify::ChangeNotifyRequest {
                flags: 0,
                output_buffer_length: 4096,
                file_id: crate::types::FileId {
                    persistent: 1,
                    volatile: 2,
                },
                completion_filter: 0xFF,
            };
            c.execute(Command::ChangeNotify, &req, Some(TreeId(1)))
                .await
        })
    };

    let outcome = finish(watching, "the CHANGE_NOTIFY").await;
    assert!(
        matches!(outcome, Err(Error::ServerUnresponsive { .. })),
        "a watcher on a dead session has to be told, got {outcome:?}"
    );
    assert!(
        server.echo_count() >= 2,
        "the verdict has to rest on probes, saw {}",
        server.echo_count()
    );
}

/// A probe answered with an error is still a probe answered.
///
/// `STATUS_NETWORK_SESSION_EXPIRED` is the realistic case: the session needs
/// re-establishing, but the server unmistakably put a frame on the wire, which
/// is the only question the probe asks. Reading it as death would retire the
/// keepalive for the life of a connection a consumer is about to re-authenticate
/// on — and silently, since nothing announces a keepalive that stopped.
#[tokio::test]
async fn a_probe_the_server_answers_with_an_error_still_counts_as_alive() {
    let server = ScriptedServer::new(Answer::EchoExpired);
    let conn = connect(&server);
    conn.set_response_timeout(None); // the deadline is not what is under test

    let write = spawn_write(&conn);
    server.wait_for_request(Command::Write).await;

    // Well past the point where two unanswered probes would have declared the
    // session dead.
    let metrics = conn.clone();
    wait_until("several probe rounds to go by", || {
        metrics.metrics().keepalive_probes_sent >= 4
    })
    .await;

    assert_eq!(
        conn.metrics().keepalive_failures,
        0,
        "an answered probe is an answered probe, whatever status it carried"
    );
    assert!(
        !conn.diagnostics().disconnected,
        "the session was torn down over a server that was demonstrably talking"
    );
    assert!(
        !write.is_finished(),
        "the write should still be outstanding"
    );
    write.abort();
}
