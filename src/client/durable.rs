//! Durable handles: an open that outlives the connection carrying it.
//!
//! A 768-file copy to a NAS used to end at the first blip. M2 made the blip
//! visible and M3.1 made the connection come back, but a write that was
//! halfway through a 4 GB file still started that file over. A durable handle
//! is what turns "start again" into "carry on": the server keeps the open
//! alive for a while after the connection dies, and the client claims it back.
//!
//! ## The data-safety rule this module exists to enforce
//!
//! Reclaiming the wrong handle writes bytes into the wrong file, which is far
//! worse than a failed transfer. So a reclaim here is not "the server said
//! yes"; it is **two independent proofs**, and anything less closes the handle
//! and fails:
//!
//! 1. **The server matched our open.** The `DH2C` reconnect context carries
//!    the 16-byte `CreateGuid` this client chose at open time and the server
//!    stored with the open. MS-SMB2 § 3.3.5.9.12 makes the server compare it,
//!    so a grant means it found *this client's* open rather than something
//!    else living at the same `FileId`. This is why only SMB 3.x v2 handles
//!    are ever reclaimed — see [`crate::msg::create_context`] for why v1's
//!    `FileId`-only shape is not good enough.
//! 2. **The open still points at the same bytes.** The `QFid` context returns
//!    the file's on-disk identity (volume id + inode). It is recorded at open
//!    and compared after the reclaim. This one does not depend on the server
//!    implementing the `CreateGuid` comparison correctly, which is the point
//!    of having two.
//!
//! A server that will not answer `QFid` gets no resume from this crate. That
//! is deliberately strict: `QFid` costs no round trip (it rides on a CREATE we
//! were sending anyway) and both Samba and Windows answer it, so declining to
//! guess costs a rare restarted transfer and buys the guarantee that a resumed
//! write never lands in a stranger's file.
//!
//! ## Getting one at all
//!
//! ⚠️ The server only grants a durable handle when the CREATE also asks for a
//! batch oplock or a handle-caching lease (MS-SMB2 § 3.3.5.9.10). This module
//! asks for a batch oplock, which has a cost worth knowing about: while we
//! hold one, another client opening the same file makes the server send us an
//! oplock break and wait for our acknowledgment before letting them proceed.
//! That is why durable opens are a separate, opt-in method rather than the
//! default for every write.
//!
//! Everything here degrades quietly. A server on SMB 2.1, a server with
//! durable handles switched off, a share that declines the oplock: all of them
//! produce an ordinary working handle with no durability, never an error.

use log::{debug, error, info, warn};

use crate::client::connection::Connection;
use crate::error::{DurableLoss, Error, Result};
use crate::msg::create::{
    CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
};
use crate::msg::create_context::{
    self, DurableGrant, DurableReconnectV2, DurableRequestV2, OnDiskId,
};
use crate::pack::{Guid, ReadCursor, Unpack};
use crate::types::flags::FileAccessMask;
use crate::types::status::NtStatus;
use crate::types::{Command, Dialect, FileId, OplockLevel};

use super::tree::Tree;

/// `FILE_NON_DIRECTORY_FILE` (MS-SMB2 § 2.2.13).
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

/// A write handle the server has promised to keep alive across a disconnect,
/// plus everything needed to prove a reclaimed one is the same file.
///
/// Obtained from [`Tree::open_file_durable`] and spent by
/// [`Tree::reclaim_durable_handle`]. Cheap to copy and safe to hold across a
/// reconnect — that is its whole job — but ❌ never construct one by hand or
/// copy the `create_guid` between files: it is the token the server matches
/// on, and reusing it is how a reclaim finds the wrong open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableHandle {
    /// The handle as the current session knows it. Replaced on every
    /// successful reclaim.
    pub file_id: FileId,
    /// What the server promised.
    pub grant: DurableGrant,
    /// The file's identity on the server's disk, captured at open. The
    /// client-side half of the proof.
    identity: OnDiskId,
    /// Our proof of ownership, echoed back in the reconnect context.
    create_guid: Guid,
    /// The connection generation this handle was last valid on. A handle whose
    /// generation matches the connection's has not missed a reconnect.
    generation: u64,
}

impl DurableHandle {
    /// The file's on-disk identity: volume id plus inode, as the server sees
    /// it.
    pub fn identity(&self) -> OnDiskId {
        self.identity
    }

    /// Whether this handle belongs to the session `conn` currently has.
    ///
    /// `false` means a reconnect has happened since the handle was obtained,
    /// so it must be reclaimed before use.
    pub fn is_current(&self, conn: &Connection) -> bool {
        self.generation == conn.generation()
    }
}

/// What an open produced: the handle, its size, and durability if the server
/// granted any.
#[derive(Debug, Clone, Copy)]
pub struct DurableOpen {
    /// The handle to write through.
    pub file_id: FileId,
    /// The file's size at open.
    pub size: u64,
    /// `Some` when the server promised to keep this open across a disconnect.
    /// `None` is normal and not an error: an SMB 2.1 server, a server with
    /// durable handles off, or one that declined the batch oplock all land
    /// here, and the handle works fine — it just cannot be resumed.
    pub durable: Option<DurableHandle>,
}

impl Tree {
    /// Open (or create) a file for writing, asking for a handle that survives
    /// a disconnect.
    ///
    /// Same as [`open_file_readwrite`](Tree::open_file_readwrite) plus a batch
    /// oplock and the two create contexts that make a later resume provable.
    /// Read the module docs before using it: the batch oplock is not free for
    /// other clients, and a `None` in [`DurableOpen::durable`] is the normal
    /// outcome on servers that do not support this.
    ///
    /// The handle is opened non-truncating (`FileOpenIf`), because the point
    /// of resuming is to keep the bytes already written.
    pub async fn open_file_durable(
        &self,
        conn: &mut Connection,
        path: &str,
    ) -> Result<DurableOpen> {
        let create_guid = crate::client::connection::random_guid();
        // A server below SMB 3.0 has only the v1 contexts, whose reclaim this
        // crate refuses to perform. Asking anyway would get us a batch oplock
        // and its costs in exchange for nothing.
        let durable_possible = conn.params().is_some_and(|p| p.dialect >= Dialect::Smb3_0);

        let mut contexts = Vec::new();
        if durable_possible {
            contexts.push(
                DurableRequestV2 {
                    // The server knows its own resource limits and clamps
                    // whatever we ask for, so asking for a specific window
                    // only invites a smaller one.
                    timeout_ms: 0,
                    persistent: false,
                    create_guid,
                }
                .context(),
            );
        }
        contexts.push(OnDiskId::request());

        let req = CreateRequest {
            requested_oplock_level: if durable_possible {
                // The price of durability: without a batch oplock (or a
                // handle-caching lease) the server ignores the DH2Q context
                // entirely (MS-SMB2 § 3.3.5.9.10).
                OplockLevel::Batch
            } else {
                OplockLevel::None
            },
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_DATA
                    | FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: FILE_ATTRIBUTE_NORMAL,
            share_access: ShareAccess(ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE),
            create_disposition: CreateDisposition::FileOpenIf,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: self.format_path(path),
            create_contexts: create_context::pack_contexts(&contexts),
        };

        let frame = conn
            .execute(Command::Create, &req, Some(self.tree_id))
            .await?;
        if frame.header.status != NtStatus::SUCCESS {
            return Err(Error::Protocol {
                status: frame.header.status,
                command: Command::Create,
            });
        }
        let resp = CreateResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        let answered = create_context::parse_contexts(&resp.create_contexts)?;

        let grant = create_context::find(&answered, create_context::NAME_DH2Q)
            .map(|c| DurableGrant::from_bytes(&c.data))
            .transpose()?;
        let identity = create_context::find(&answered, create_context::NAME_QFID)
            .map(|c| OnDiskId::from_bytes(&c.data))
            .transpose()?;

        // Both proofs or nothing. A handle we could not later prove is the
        // same file must not be presented as resumable, because the caller
        // would build a resume on it and we would have to refuse at the worst
        // possible moment.
        let durable = match (grant, identity) {
            (Some(grant), Some(identity)) => {
                info!(
                    "durable: {} opened with a durable handle, server holds it {} ms{}",
                    path,
                    grant.timeout_ms,
                    if grant.persistent {
                        " (persistent)"
                    } else {
                        ""
                    }
                );
                // So a break notification, which arrives with no usable tree
                // id of its own, can be answered on the right tree.
                conn.register_oplock(resp.file_id, self.tree_id);
                Some(DurableHandle {
                    file_id: resp.file_id,
                    grant,
                    identity,
                    create_guid,
                    generation: conn.generation(),
                })
            }
            (Some(_), None) => {
                warn!(
                    "durable: {path} got a durable handle but the server would not answer \
                     QFid, so a reclaim could never be proven to be the same file; \
                     treating the handle as non-resumable"
                );
                None
            }
            (None, _) => {
                debug!(
                    "durable: {path} opened without durability (server declined or does \
                     not support it); an interrupted write will restart"
                );
                None
            }
        };

        Ok(DurableOpen {
            file_id: resp.file_id,
            size: resp.end_of_file,
            durable,
        })
    }

    /// Claim a durable open back after a reconnect, or fail rather than guess.
    ///
    /// `conn` must be a live, authenticated connection to the same server, and
    /// `self` a tree connect to the same share, under the same credentials —
    /// that is what the server checks before it will even look at the handle.
    /// `path` must be the path the handle was opened at.
    ///
    /// On success the returned handle carries the new `FileId` and the caller
    /// can resume writing at whatever offset it had reached. On failure
    /// **nothing is left open on the server**: a handle that came back
    /// unprovable is closed before the error is returned.
    ///
    /// Errors are [`Error::DurableHandleLost`], whose [`DurableLoss`] says
    /// which of the guarantees did not hold. All of them mean the same thing
    /// to a caller: reopen and rewrite the file from the start.
    pub async fn reclaim_durable_handle(
        &self,
        conn: &mut Connection,
        handle: &DurableHandle,
        path: &str,
    ) -> Result<DurableHandle> {
        let lost = |reason| Error::DurableHandleLost {
            path: path.to_string(),
            reason,
        };

        let contexts = create_context::pack_contexts(&[
            DurableReconnectV2 {
                file_id: handle.file_id,
                create_guid: handle.create_guid,
                persistent: handle.grant.persistent,
            }
            .context(),
            // Asked again so the answer can be compared. ❌ Don't drop this to
            // save bytes: it is the half of the proof that does not rely on
            // the server comparing the CreateGuid correctly.
            OnDiskId::request(),
        ]);

        let req = CreateRequest {
            requested_oplock_level: OplockLevel::Batch,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::new(
                FileAccessMask::FILE_READ_DATA
                    | FileAccessMask::FILE_WRITE_DATA
                    | FileAccessMask::FILE_READ_ATTRIBUTES
                    | FileAccessMask::FILE_WRITE_ATTRIBUTES
                    | FileAccessMask::SYNCHRONIZE,
            ),
            file_attributes: FILE_ATTRIBUTE_NORMAL,
            share_access: ShareAccess(ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_WRITE),
            create_disposition: CreateDisposition::FileOpen,
            create_options: FILE_NON_DIRECTORY_FILE,
            name: self.format_path(path),
            create_contexts: contexts,
        };

        let frame = conn
            .execute(Command::Create, &req, Some(self.tree_id))
            .await?;
        if frame.header.status != NtStatus::SUCCESS {
            debug!(
                "durable: the server would not give {path} back ({}); the open expired \
                 or the server restarted",
                frame.header.status
            );
            return Err(lost(DurableLoss::Expired));
        }

        let resp = CreateResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        let answered = create_context::parse_contexts(&resp.create_contexts)?;
        let Some(identity) = create_context::find(&answered, create_context::NAME_QFID)
            .map(|c| OnDiskId::from_bytes(&c.data))
            .transpose()?
        else {
            // It answered the reclaim but not the question. We hold a handle we
            // cannot vouch for, so put it back.
            warn!(
                "durable: {path} came back without an on-disk id, so nothing about it \
                 can be proven; closing it and starting over"
            );
            let _ = self.close_handle(conn, resp.file_id).await;
            return Err(lost(DurableLoss::IdentityUnavailable));
        };

        if identity != handle.identity {
            // The one outcome this whole module exists to make impossible.
            // Loud, because a server reaching this is doing something the
            // protocol says it must not.
            error!(
                "durable: REFUSING a reclaimed handle for {path} -- the server matched \
                 our CreateGuid but handed back a different file (asked for volume \
                 {:#x} file {:#x}, got volume {:#x} file {:#x}). Closing it; the \
                 transfer restarts rather than writing into the wrong file.",
                handle.identity.volume_id,
                handle.identity.disk_file_id,
                identity.volume_id,
                identity.disk_file_id,
            );
            let _ = self.close_handle(conn, resp.file_id).await;
            return Err(lost(DurableLoss::IdentityMismatch));
        }

        info!(
            "durable: {path} reclaimed on the new session; the transfer resumes rather \
             than restarting"
        );
        conn.register_oplock(resp.file_id, self.tree_id);
        Ok(DurableHandle {
            file_id: resp.file_id,
            generation: conn.generation(),
            ..*handle
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_helpers::{
        build_close_response, build_create_error_response, build_create_response_with_contexts,
        setup_connection,
    };
    use crate::msg::create_context::CreateContext;
    use crate::transport::MockTransport;
    use crate::types::TreeId;
    use std::sync::Arc;

    const OURS: OnDiskId = OnDiskId {
        disk_file_id: 0x1234_5678,
        volume_id: 0xABCD,
    };
    /// Same volume, different inode: the shape a recycled `FileId` would take.
    const SOMEONE_ELSES: OnDiskId = OnDiskId {
        disk_file_id: 0x9999_9999,
        volume_id: 0xABCD,
    };

    fn a_tree() -> Tree {
        Tree {
            tree_id: TreeId(20),
            share_name: "test".to_string(),
            server: "test-server".to_string(),
            is_dfs: false,
            encrypt_data: false,
        }
    }

    fn smb3(conn: &mut Connection) {
        let mut params = conn.params().unwrap();
        params.dialect = Dialect::Smb3_1_1;
        conn.set_test_params(params);
    }

    fn on_disk(id: OnDiskId) -> CreateContext {
        let mut body = Vec::new();
        body.extend_from_slice(&id.disk_file_id.to_le_bytes());
        body.extend_from_slice(&id.volume_id.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        CreateContext::new(create_context::NAME_QFID, body)
    }

    fn granted(timeout_ms: u32) -> CreateContext {
        let mut body = Vec::new();
        body.extend_from_slice(&timeout_ms.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        CreateContext::new(create_context::NAME_DH2Q, body)
    }

    fn a_file_id(n: u64) -> FileId {
        FileId {
            persistent: n,
            volatile: n,
        }
    }

    /// The contexts the client actually put on the wire for request `n`.
    fn sent_contexts(mock: &MockTransport, n: usize) -> Vec<CreateContext> {
        let sent = mock.sent_message(n).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = crate::msg::header::Header::unpack(&mut cursor).unwrap();
        let req = CreateRequest::unpack(&mut cursor).unwrap();
        create_context::parse_contexts(&req.create_contexts).unwrap()
    }

    fn sent_oplock(mock: &MockTransport, n: usize) -> OplockLevel {
        let sent = mock.sent_message(n).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let _header = crate::msg::header::Header::unpack(&mut cursor).unwrap();
        CreateRequest::unpack(&mut cursor)
            .unwrap()
            .requested_oplock_level
    }

    /// Open a durable handle and hand back everything the test needs.
    async fn open_durably(mock: &Arc<MockTransport>, conn: &mut Connection) -> DurableOpen {
        mock.queue_response(build_create_response_with_contexts(
            a_file_id(1),
            0,
            &[granted(180_000), on_disk(OURS)],
        ));
        a_tree()
            .open_file_durable(conn, "big.iso")
            .await
            .expect("the open must succeed")
    }

    #[tokio::test]
    async fn an_open_the_server_backs_with_both_proofs_is_resumable() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);

        let open = open_durably(&mock, &mut conn).await;

        let durable = open.durable.expect("both proofs were answered");
        assert_eq!(durable.file_id, a_file_id(1));
        assert_eq!(durable.grant.timeout_ms, 180_000);
        assert_eq!(durable.identity(), OURS);
        assert!(durable.is_current(&conn));

        assert_eq!(
            sent_oplock(&mock, 0),
            OplockLevel::Batch,
            "without a batch oplock the server ignores the durable request \
             entirely (MS-SMB2 3.3.5.9.10)"
        );
        let contexts = sent_contexts(&mock, 0);
        assert!(create_context::find(&contexts, create_context::NAME_DH2Q).is_some());
        assert!(create_context::find(&contexts, create_context::NAME_QFID).is_some());
    }

    /// A server that will not do durable handles is normal, not an error. The
    /// caller gets a working handle that simply cannot be resumed.
    #[tokio::test]
    async fn an_open_the_server_declines_durability_on_still_returns_a_working_handle() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        mock.queue_response(build_create_response_with_contexts(
            a_file_id(1),
            4096,
            &[on_disk(OURS)], // QFid answered, no DH2Q
        ));

        let open = a_tree()
            .open_file_durable(&mut conn, "big.iso")
            .await
            .unwrap();

        assert_eq!(open.file_id, a_file_id(1));
        assert_eq!(open.size, 4096);
        assert!(
            open.durable.is_none(),
            "no grant means no resume, and that must not be an error"
        );
    }

    /// A grant with no way to prove identity is not offered as resumable.
    ///
    /// Offering it would push the failure to the worst possible moment: the
    /// caller builds a resume on the handle and we refuse mid-transfer, when
    /// the honest answer was available at open time.
    #[tokio::test]
    async fn a_grant_the_server_will_not_back_with_an_on_disk_id_is_not_resumable() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        mock.queue_response(build_create_response_with_contexts(
            a_file_id(1),
            0,
            &[granted(180_000)], // durable, but no QFid
        ));

        let open = a_tree()
            .open_file_durable(&mut conn, "big.iso")
            .await
            .unwrap();
        assert!(open.durable.is_none());
    }

    /// SMB 2.1 has only the v1 contexts, whose reclaim carries no client-chosen
    /// proof. We don't ask, so we don't take the batch oplock's costs for
    /// something we would refuse to use.
    #[tokio::test]
    async fn a_pre_smb3_server_is_never_asked_for_a_durable_handle() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock); // negotiates SMB 2.0.2
        mock.queue_response(build_create_response_with_contexts(
            a_file_id(1),
            0,
            &[on_disk(OURS)],
        ));

        let open = a_tree()
            .open_file_durable(&mut conn, "big.iso")
            .await
            .unwrap();

        assert!(open.durable.is_none());
        assert_eq!(sent_oplock(&mock, 0), OplockLevel::None);
        let contexts = sent_contexts(&mock, 0);
        assert!(create_context::find(&contexts, create_context::NAME_DH2Q).is_none());
    }

    // ── Reclaiming ────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_reclaim_of_the_same_file_succeeds_and_carries_the_new_handle() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        let durable = open_durably(&mock, &mut conn).await.durable.unwrap();

        // The server gives it back under a new FileId, same file.
        mock.queue_response(build_create_response_with_contexts(
            a_file_id(2),
            0,
            &[on_disk(OURS)],
        ));
        let reclaimed = a_tree()
            .reclaim_durable_handle(&mut conn, &durable, "big.iso")
            .await
            .expect("same file, both proofs held");

        assert_eq!(
            reclaimed.file_id,
            a_file_id(2),
            "the caller must write through the new handle, not the dead one"
        );
        assert_eq!(reclaimed.identity(), OURS);
    }

    /// The reconnect context has to carry the guid from the *original* open.
    /// It is the token the server matches on; a fresh one would match nothing.
    #[tokio::test]
    async fn the_reconnect_context_replays_the_create_guid_from_the_open() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        let durable = open_durably(&mock, &mut conn).await.durable.unwrap();

        let opened = sent_contexts(&mock, 0);
        let dh2q = create_context::find(&opened, create_context::NAME_DH2Q).unwrap();
        let guid_at_open = &dh2q.data[16..32];

        mock.queue_response(build_create_response_with_contexts(
            a_file_id(2),
            0,
            &[on_disk(OURS)],
        ));
        a_tree()
            .reclaim_durable_handle(&mut conn, &durable, "big.iso")
            .await
            .unwrap();

        let reclaimed = sent_contexts(&mock, 1);
        let dh2c = create_context::find(&reclaimed, create_context::NAME_DH2C)
            .expect("the reclaim must carry a DH2C context");
        assert_eq!(
            &dh2c.data[16..32],
            guid_at_open,
            "the guid the server stored with the open is what proves the \
             handle is ours"
        );
        assert_eq!(
            &dh2c.data[0..8],
            &durable.file_id.persistent.to_le_bytes(),
            "and the old FileId is what it looks up"
        );
        assert!(
            create_context::find(&reclaimed, create_context::NAME_QFID).is_some(),
            "asking again is the half of the proof that does not depend on the \
             server comparing the guid correctly"
        );
    }

    /// The one this whole module exists for.
    ///
    /// The server matched the `CreateGuid` and still handed back a different
    /// file. Writing through that handle would put the user's bytes in a
    /// stranger's file, which is far worse than a failed transfer, so the
    /// handle is closed and the reclaim refused.
    #[tokio::test]
    async fn a_reclaim_that_comes_back_as_a_different_file_is_refused_and_closed() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        let durable = open_durably(&mock, &mut conn).await.durable.unwrap();

        mock.queue_response(build_create_response_with_contexts(
            a_file_id(2),
            0,
            &[on_disk(SOMEONE_ELSES)],
        ));
        mock.queue_response(build_close_response());

        let outcome = a_tree()
            .reclaim_durable_handle(&mut conn, &durable, "big.iso")
            .await;

        assert!(
            matches!(
                outcome,
                Err(Error::DurableHandleLost {
                    reason: DurableLoss::IdentityMismatch,
                    ..
                })
            ),
            "expected a refusal naming the mismatch, got {outcome:?}"
        );
        assert_eq!(
            mock.sent_count(),
            3,
            "the handle we refused must be closed, not leaked on the server: \
             open, reclaim, close"
        );
        let closed = mock.sent_message(2).unwrap();
        let mut cursor = ReadCursor::new(&closed);
        let header = crate::msg::header::Header::unpack(&mut cursor).unwrap();
        assert_eq!(header.command, Command::Close);
    }

    /// A reclaim the server will not vouch for is refused too. "It gave the
    /// handle back" is not one of the two proofs.
    #[tokio::test]
    async fn a_reclaim_with_no_on_disk_id_is_refused_and_closed() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        let durable = open_durably(&mock, &mut conn).await.durable.unwrap();

        mock.queue_response(build_create_response_with_contexts(a_file_id(2), 0, &[]));
        mock.queue_response(build_close_response());

        let outcome = a_tree()
            .reclaim_durable_handle(&mut conn, &durable, "big.iso")
            .await;

        assert!(
            matches!(
                outcome,
                Err(Error::DurableHandleLost {
                    reason: DurableLoss::IdentityUnavailable,
                    ..
                })
            ),
            "got {outcome:?}"
        );
        assert_eq!(mock.sent_count(), 3, "the unprovable handle was closed");
    }

    /// The routine failure: the open timed out, or the server restarted. A
    /// durable handle survives a dead connection, not a dead server.
    #[tokio::test]
    async fn a_reclaim_the_server_rejects_reports_the_open_as_expired() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        let durable = open_durably(&mock, &mut conn).await.durable.unwrap();

        mock.queue_response(build_create_error_response(NtStatus::OBJECT_NAME_NOT_FOUND));

        let outcome = a_tree()
            .reclaim_durable_handle(&mut conn, &durable, "big.iso")
            .await;

        assert!(
            matches!(
                outcome,
                Err(Error::DurableHandleLost {
                    reason: DurableLoss::Expired,
                    ..
                })
            ),
            "got {outcome:?}"
        );
        assert_eq!(
            mock.sent_count(),
            2,
            "nothing was opened, so there is nothing to close"
        );
    }

    /// A handle knows which session it belongs to, so a caller can tell
    /// "reconnect happened, reclaim first" from "still fine, keep writing"
    /// without tracking it separately.
    #[tokio::test]
    async fn a_handle_knows_it_has_outlived_its_session() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = setup_connection(&mock);
        smb3(&mut conn);
        let durable = open_durably(&mock, &mut conn).await.durable.unwrap();
        assert!(durable.is_current(&conn));

        // A `DurableHandle` from generation 0 against a connection that has
        // since been revived.
        let stale = DurableHandle {
            generation: 0,
            ..durable
        };
        let after_a_reconnect = DurableHandle {
            generation: 1,
            ..durable
        };
        assert!(stale.is_current(&conn), "generation 0 is what conn is on");
        assert!(!after_a_reconnect.is_current(&conn));
    }
}

/// The batch oplock's bill, and who pays it.
#[cfg(test)]
mod oplock_break_tests {
    use super::*;
    use crate::client::connection::{pack_message, NegotiatedParams};
    use crate::client::test_helpers::build_create_response_with_contexts;
    use crate::msg::create_context::CreateContext;
    use crate::msg::header::Header;
    use crate::msg::oplock_break::OplockBreak;
    use crate::pack::Unpack;
    use crate::transport::MockTransport;
    use crate::types::flags::Capabilities;
    use crate::types::{MessageId, SessionId, TreeId};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const THE_TREE: TreeId = TreeId(20);
    const OURS: OnDiskId = OnDiskId {
        disk_file_id: 7,
        volume_id: 9,
    };

    /// A connection whose responses carry real message ids, so an unsolicited
    /// frame can be delivered without the mock's auto-rewrite pairing it
    /// against a send that never happened.
    fn plain_connection(mock: &Arc<MockTransport>) -> Connection {
        let mut conn =
            Connection::from_transport(Box::new(mock.clone()), Box::new(mock.clone()), "test");
        conn.set_test_params(NegotiatedParams {
            dialect: Dialect::Smb3_1_1,
            max_read_size: 65536,
            max_write_size: 65536,
            max_transact_size: 65536,
            server_guid: Guid::ZERO,
            signing_required: false,
            capabilities: Capabilities::default(),
            gmac_negotiated: false,
            cipher: None,
            compression_supported: false,
        });
        conn.set_session_id(SessionId(1));
        conn.set_credits(512);
        conn
    }

    fn contexts(id: OnDiskId, timeout_ms: u32) -> Vec<CreateContext> {
        let mut grant = Vec::new();
        grant.extend_from_slice(&timeout_ms.to_le_bytes());
        grant.extend_from_slice(&0u32.to_le_bytes());
        let mut qfid = Vec::new();
        qfid.extend_from_slice(&id.disk_file_id.to_le_bytes());
        qfid.extend_from_slice(&id.volume_id.to_le_bytes());
        qfid.extend_from_slice(&[0u8; 16]);
        vec![
            CreateContext::new(create_context::NAME_DH2Q, grant),
            CreateContext::new(create_context::NAME_QFID, qfid),
        ]
    }

    fn a_break(file_id: FileId) -> Vec<u8> {
        let mut h = Header::new_request(Command::OplockBreak);
        h.flags.set_response();
        h.message_id = MessageId::UNSOLICITED;
        h.credits = 1;
        pack_message(
            &h,
            &OplockBreak {
                oplock_level: OplockLevel::LevelII,
                file_id,
            },
        )
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn a_tree() -> Tree {
        Tree {
            tree_id: THE_TREE,
            share_name: "test".to_string(),
            server: "test".to_string(),
            is_dfs: false,
            encrypt_data: false,
        }
    }

    /// Holding a batch oplock costs *other* clients: until we answer a break,
    /// whoever tried to open the file waits out the server's break timeout,
    /// which is around 35 s on both Samba and Windows. So we answer.
    #[tokio::test]
    async fn an_oplock_break_is_acknowledged_so_the_other_client_is_not_left_waiting() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = plain_connection(&mock);
        let handle_id = FileId {
            persistent: 5,
            volatile: 5,
        };
        mock.queue_response(build_create_response_with_contexts(
            handle_id,
            0,
            &contexts(OURS, 180_000),
        ));
        let open = a_tree()
            .open_file_durable(&mut conn, "big.iso")
            .await
            .unwrap();
        assert!(open.durable.is_some());

        mock.queue_response(a_break(handle_id));
        wait_for("the acknowledgment to be sent", || mock.sent_count() >= 2).await;

        let sent = mock.sent_message(1).unwrap();
        let mut cursor = ReadCursor::new(&sent);
        let header = Header::unpack(&mut cursor).unwrap();
        assert_eq!(header.command, Command::OplockBreak);
        assert_eq!(
            header.tree_id,
            Some(THE_TREE),
            "the acknowledgment has to name the tree the open belongs to \
             (MS-SMB2 2.2.24.1); on the wrong one the server rejects it and the \
             other client waits anyway"
        );
        let ack = OplockBreak::unpack(&mut cursor).unwrap();
        assert_eq!(ack.file_id, handle_id);
        assert_eq!(
            ack.oplock_level,
            OplockLevel::None,
            "we only ever took the oplock to get durability, and durability is \
             already gone by the time a break arrives"
        );
    }

    /// A break for a handle we hold no oplock on is not ours to answer, and
    /// guessing a tree id would produce an acknowledgment the server rejects.
    #[tokio::test]
    async fn a_break_for_a_handle_we_never_oplocked_is_left_alone() {
        let mock = Arc::new(MockTransport::new());
        let conn = plain_connection(&mock);

        mock.queue_response(a_break(FileId {
            persistent: 999,
            volatile: 999,
        }));
        // Long enough that an acknowledgment would certainly have been sent.
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(mock.sent_count(), 0, "nothing should have been sent");
        assert_eq!(conn.metrics().unsolicited_notifications_received, 1);
    }

    /// Closing a handle retires its oplock bookkeeping, so a break arriving
    /// afterwards is not acknowledged on a handle that is already gone.
    #[tokio::test]
    async fn closing_a_handle_retires_its_oplock_bookkeeping() {
        let mock = Arc::new(MockTransport::new());
        let mut conn = plain_connection(&mock);
        let handle_id = FileId {
            persistent: 5,
            volatile: 5,
        };
        mock.queue_response(build_create_response_with_contexts(
            handle_id,
            0,
            &contexts(OURS, 180_000),
        ));
        a_tree()
            .open_file_durable(&mut conn, "big.iso")
            .await
            .unwrap();

        // The canned responses all carry message id 0, and this connection has
        // no auto-rewrite, so rewind the sequence for the second exchange.
        conn.set_next_message_id(0);
        mock.queue_response(crate::client::test_helpers::build_close_response());
        a_tree().close_handle(&mut conn, handle_id).await.unwrap();
        let sent_after_close = mock.sent_count();

        mock.queue_response(a_break(handle_id));
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(
            mock.sent_count(),
            sent_after_close,
            "a break for a closed handle must not produce an acknowledgment"
        );
    }
}
