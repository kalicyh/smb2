//! Error types for the SMB2 library.

use crate::types::status::NtStatus;
use crate::types::Command;
use thiserror::Error;

/// Top-level error type for SMB2 operations.
#[derive(Debug, Error)]
pub enum Error {
    /// The data is malformed or does not match the expected format.
    #[error("Invalid data: {message}")]
    InvalidData {
        /// Description of what went wrong.
        message: String,
    },

    /// The server returned a non-success NTSTATUS.
    #[error("Protocol error: {status} during {command:?}")]
    Protocol {
        /// The NTSTATUS code from the response header.
        status: NtStatus,
        /// The command that triggered the error.
        command: Command,
    },

    /// Authentication failed.
    #[error("Authentication failed: {message}")]
    Auth {
        /// Description of what went wrong.
        message: String,
    },

    /// An I/O or transport error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The operation timed out.
    #[error("Operation timed out")]
    Timeout,

    /// The connection was lost.
    #[error("Disconnected from server")]
    Disconnected,

    /// The path requires DFS referral resolution.
    ///
    /// The server returned `STATUS_PATH_NOT_COVERED`, meaning this path
    /// lives on a different server via DFS. The caller can query for a
    /// referral or display a helpful message.
    #[error("DFS referral required for path: {path}")]
    DfsReferralRequired {
        /// The path that needs DFS resolution.
        path: String,
    },

    /// The operation was cancelled by the caller (via progress callback).
    #[error("Operation cancelled")]
    Cancelled,

    /// The session expired and reauthentication failed.
    ///
    /// The pipeline normally handles `STATUS_NETWORK_SESSION_EXPIRED`
    /// transparently by reauthenticating. This error surfaces only
    /// when reauthentication itself fails.
    #[error("Session expired and reauthentication failed")]
    SessionExpired,

    /// The file is larger than a single READ can return, so a one-shot read
    /// would truncate it.
    ///
    /// Returned by [`Tree::read_file`](crate::Tree::read_file) and
    /// [`Tree::read_file_compound`](crate::Tree::read_file_compound) when the
    /// file's size exceeds the server's negotiated per-READ maximum
    /// (`MaxReadSize`). Those paths issue a single READ, so a larger file can't
    /// come back whole — rather than silently dropping the tail, they fail with
    /// this. Switch to [`Tree::read_file_pipelined`](crate::Tree::read_file_pipelined),
    /// which reads the whole file in a sliding window of chunked READs
    /// regardless of size. Classifies as [`ErrorKind::TooLarge`].
    #[error(
        "file is {size} bytes, larger than the server's {max_read}-byte \
         single-read limit; use read_file_pipelined for files this size"
    )]
    FileTooLargeForSingleRead {
        /// The file's size in bytes.
        size: u64,
        /// The server's negotiated maximum bytes per READ (`MaxReadSize`).
        max_read: u32,
    },
}

impl Error {
    /// Create an `InvalidData` error with the given message.
    pub fn invalid_data(msg: impl Into<String>) -> Self {
        Error::InvalidData {
            message: msg.into(),
        }
    }

    /// Returns `true` if this error is potentially transient and
    /// the operation could succeed on retry.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Timeout
                | Error::Disconnected
                | Error::Protocol {
                    status: NtStatus::INSUFFICIENT_RESOURCES,
                    ..
                }
                | Error::Protocol {
                    status: NtStatus::INSUFF_SERVER_RESOURCES,
                    ..
                }
        )
    }

    /// Returns the NTSTATUS code if this is a protocol error.
    pub fn status(&self) -> Option<NtStatus> {
        match self {
            Error::Protocol { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// High-level error classification.
///
/// Maps protocol-level NTSTATUS codes and other errors into categories
/// that consumers can match on without understanding SMB internals.
///
/// ```no_run
/// # async fn example(client: &mut smb2::SmbClient, share: &mut smb2::Tree) -> Result<(), smb2::Error> {
/// use smb2::ErrorKind;
///
/// match client.read_file(share, "photo.jpg").await {
///     Ok(data) => println!("read {} bytes", data.len()),
///     Err(e) => match e.kind() {
///         ErrorKind::NotFound => println!("file doesn't exist"),
///         ErrorKind::AlreadyExists => println!("name is already taken"),
///         ErrorKind::AccessDenied => println!("no permission"),
///         ErrorKind::SigningRequired => println!("server requires signing, use credentials"),
///         ErrorKind::AuthRequired => println!("server requires authentication"),
///         ErrorKind::SharingViolation => println!("file is in use by another client"),
///         ErrorKind::IsADirectory => println!("path is a directory, not a file"),
///         ErrorKind::NotADirectory => println!("path is a file, not a directory"),
///         ErrorKind::DiskFull => println!("volume is full"),
///         ErrorKind::ConnectionLost => { client.reconnect().await?; }
///         _ => return Err(e),
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Stability
///
/// `ErrorKind` is `#[non_exhaustive]`: future versions may add variants for
/// status codes that currently fall through to [`ErrorKind::Other`]. Match
/// statements should always include a `_` arm. Adding a variant is treated
/// as a non-breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The server requires authentication (guest/anonymous not allowed).
    AuthRequired,
    /// The server requires message signing (guest sessions are unsigned).
    SigningRequired,
    /// Permission denied (valid credentials, but no access to this resource).
    AccessDenied,
    /// The file, directory, or share was not found.
    NotFound,
    /// A file or directory with the given name already exists.
    ///
    /// Returned by `Create` (and operations that wrap it, like `create_directory`)
    /// when the target name is taken. Useful for callers that want to merge into
    /// an existing directory or surface a friendly "name already taken" message.
    AlreadyExists,
    /// The file is in use by another client.
    SharingViolation,
    /// The target path is a directory, but the operation expected a file.
    ///
    /// Typically seen when calling `delete_file` against a directory entry —
    /// the caller can fall back to `delete_directory` after detecting this.
    IsADirectory,
    /// The target path is a file, but the operation expected a directory.
    ///
    /// Typically seen when calling `list_directory` against a file entry.
    NotADirectory,
    /// The volume is full (write failed).
    DiskFull,
    /// The network connection was lost.
    ConnectionLost,
    /// The operation timed out.
    TimedOut,
    /// The operation was cancelled by the caller.
    Cancelled,
    /// The session expired (call `reconnect()`).
    SessionExpired,
    /// The path requires DFS referral resolution.
    DfsReferral,
    /// Invalid data or malformed response.
    InvalidData,
    /// The file is too large for a single-read path.
    ///
    /// Returned by [`Tree::read_file`](crate::Tree::read_file) /
    /// [`read_file_compound`](crate::Tree::read_file_compound) when the file
    /// exceeds the server's per-READ maximum. Switch to
    /// [`read_file_pipelined`](crate::Tree::read_file_pipelined), which reads
    /// any size in chunked, pipelined READs.
    TooLarge,
    /// An I/O error (transport or callback). Not necessarily a connection loss.
    ///
    /// Distinct from `ConnectionLost`: the connection may still be usable.
    /// For example, a callback error in `write_file_streamed` produces `Io`,
    /// but the connection is still in a clean state.
    Io,
    /// The server does not support the requested operation.
    ///
    /// Returned when the server rejects an operation it does not implement --
    /// for example, an older Samba build or NAS firmware that lacks server-side
    /// copy. Consumers branch on this to fall back to a client-side path (for
    /// server-side copy, a plain read-then-write). Maps from
    /// `STATUS_NOT_SUPPORTED`, `STATUS_INVALID_DEVICE_REQUEST`, and
    /// `STATUS_NOT_IMPLEMENTED`.
    Unsupported,
    /// A protocol error not covered by other variants.
    ///
    /// Use [`Error::status()`] to get the raw NTSTATUS code. Some defined
    /// `NtStatus` codes deliberately fall through here today
    /// (`OBJECT_NAME_INVALID`, `DELETE_PENDING`, `INSUFFICIENT_RESOURCES`,
    /// `INSUFF_SERVER_RESOURCES`, and similar) — they don't yet have a
    /// dedicated `ErrorKind` because no consumer needs to branch on them.
    /// Promoting one to its own variant is non-breaking.
    Other,
}

impl Error {
    /// Classify this error into a high-level category.
    ///
    /// Consumers can match on [`ErrorKind`] without understanding raw
    /// NTSTATUS codes. For the underlying status code, use [`status()`](Self::status).
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::InvalidData { .. } => ErrorKind::InvalidData,
            Error::Auth { .. } => ErrorKind::AuthRequired,
            Error::Io(_) => ErrorKind::Io,
            Error::Disconnected => ErrorKind::ConnectionLost,
            Error::Timeout => ErrorKind::TimedOut,
            Error::Cancelled => ErrorKind::Cancelled,
            Error::SessionExpired => ErrorKind::SessionExpired,
            Error::DfsReferralRequired { .. } => ErrorKind::DfsReferral,
            Error::FileTooLargeForSingleRead { .. } => ErrorKind::TooLarge,
            Error::Protocol { status, .. } => classify_status(*status),
        }
    }
}

/// Map an NTSTATUS to an ErrorKind.
fn classify_status(status: NtStatus) -> ErrorKind {
    match status {
        // Auth / signing -- the logon-rejection family. The credentials or the
        // account itself were refused (bad password, account disabled/expired/
        // locked, password expired, or a time/workstation restriction). All mean
        // the same thing to a consumer: this logon won't work, supply different
        // credentials. A guest/anonymous SessionSetup that the server rejects
        // (macOS smbd answers with STATUS_ACCOUNT_RESTRICTION) lands here too.
        NtStatus::LOGON_FAILURE
        | NtStatus::ACCOUNT_RESTRICTION
        | NtStatus::INVALID_LOGON_HOURS
        | NtStatus::INVALID_WORKSTATION
        | NtStatus::PASSWORD_EXPIRED
        | NtStatus::ACCOUNT_DISABLED
        | NtStatus::ACCOUNT_EXPIRED
        | NtStatus::PASSWORD_MUST_CHANGE
        | NtStatus::ACCOUNT_LOCKED_OUT => ErrorKind::AuthRequired,
        NtStatus::ACCESS_DENIED => {
            // Could be signing-required or genuinely access-denied.
            // Callers with NegotiatedParams context can distinguish further.
            // Default to AccessDenied; SmbClient methods can upgrade to
            // SigningRequired when signing_required is true.
            ErrorKind::AccessDenied
        }

        // Not found
        NtStatus::NO_SUCH_FILE
        | NtStatus::OBJECT_NAME_NOT_FOUND
        | NtStatus::OBJECT_PATH_NOT_FOUND
        | NtStatus::BAD_NETWORK_NAME => ErrorKind::NotFound,

        // Already exists
        NtStatus::OBJECT_NAME_COLLISION => ErrorKind::AlreadyExists,

        // Wrong file type
        NtStatus::FILE_IS_A_DIRECTORY => ErrorKind::IsADirectory,
        NtStatus::NOT_A_DIRECTORY => ErrorKind::NotADirectory,

        // Sharing / locking
        NtStatus::SHARING_VIOLATION | NtStatus::FILE_LOCK_CONFLICT => ErrorKind::SharingViolation,

        // Disk full
        NtStatus::DISK_FULL => ErrorKind::DiskFull,

        // Session expired
        NtStatus::NETWORK_SESSION_EXPIRED => ErrorKind::SessionExpired,

        // Connection
        NtStatus::NETWORK_NAME_DELETED | NtStatus::USER_SESSION_DELETED => {
            ErrorKind::ConnectionLost
        }

        // DFS
        NtStatus::PATH_NOT_COVERED => ErrorKind::DfsReferral,

        // Unsupported operation (server lacks the feature, e.g. server-side copy)
        NtStatus::NOT_SUPPORTED | NtStatus::INVALID_DEVICE_REQUEST | NtStatus::NOT_IMPLEMENTED => {
            ErrorKind::Unsupported
        }

        // Everything else
        _ => ErrorKind::Other,
    }
}

/// A `Result` type alias using the crate's [`Error`](enum@Error) type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Documents the full contract between `NtStatus` codes and `ErrorKind`.
    ///
    /// Every code listed here is asserted to map to its expected variant. When
    /// adding a new `NtStatus` to `types/status.rs`, also add a row here — either
    /// pointing at a dedicated `ErrorKind`, or `ErrorKind::Other` if there is
    /// genuinely no consumer-meaningful classification yet. The `classify_status_contract`
    /// test then asserts every row maps the way this table says it should, so the
    /// table stays in sync with what `classify_status` actually does.
    const STATUS_CLASSIFICATION_CONTRACT: &[(NtStatus, ErrorKind)] = &[
        // Auth / signing -- the logon-rejection family (credentials or the
        // account itself were refused; the caller needs different credentials)
        (NtStatus::LOGON_FAILURE, ErrorKind::AuthRequired),
        (NtStatus::ACCOUNT_RESTRICTION, ErrorKind::AuthRequired),
        (NtStatus::INVALID_LOGON_HOURS, ErrorKind::AuthRequired),
        (NtStatus::INVALID_WORKSTATION, ErrorKind::AuthRequired),
        (NtStatus::PASSWORD_EXPIRED, ErrorKind::AuthRequired),
        (NtStatus::ACCOUNT_DISABLED, ErrorKind::AuthRequired),
        (NtStatus::ACCOUNT_EXPIRED, ErrorKind::AuthRequired),
        (NtStatus::PASSWORD_MUST_CHANGE, ErrorKind::AuthRequired),
        (NtStatus::ACCOUNT_LOCKED_OUT, ErrorKind::AuthRequired),
        (NtStatus::ACCESS_DENIED, ErrorKind::AccessDenied),
        // Not found
        (NtStatus::NO_SUCH_FILE, ErrorKind::NotFound),
        (NtStatus::OBJECT_NAME_NOT_FOUND, ErrorKind::NotFound),
        (NtStatus::OBJECT_PATH_NOT_FOUND, ErrorKind::NotFound),
        (NtStatus::BAD_NETWORK_NAME, ErrorKind::NotFound),
        // Already exists
        (NtStatus::OBJECT_NAME_COLLISION, ErrorKind::AlreadyExists),
        // Wrong file type
        (NtStatus::FILE_IS_A_DIRECTORY, ErrorKind::IsADirectory),
        (NtStatus::NOT_A_DIRECTORY, ErrorKind::NotADirectory),
        // Sharing / locking
        (NtStatus::SHARING_VIOLATION, ErrorKind::SharingViolation),
        (NtStatus::FILE_LOCK_CONFLICT, ErrorKind::SharingViolation),
        // Disk
        (NtStatus::DISK_FULL, ErrorKind::DiskFull),
        // Connection / session
        (NtStatus::NETWORK_NAME_DELETED, ErrorKind::ConnectionLost),
        (NtStatus::USER_SESSION_DELETED, ErrorKind::ConnectionLost),
        (NtStatus::NETWORK_SESSION_EXPIRED, ErrorKind::SessionExpired),
        // DFS
        (NtStatus::PATH_NOT_COVERED, ErrorKind::DfsReferral),
        // Unsupported operation
        (NtStatus::NOT_SUPPORTED, ErrorKind::Unsupported),
        (NtStatus::INVALID_DEVICE_REQUEST, ErrorKind::Unsupported),
        (NtStatus::NOT_IMPLEMENTED, ErrorKind::Unsupported),
        // Documented `Other` (no current consumer demand for a typed variant)
        (NtStatus::INVALID_PARAMETER, ErrorKind::Other),
        (NtStatus::DELETE_PENDING, ErrorKind::Other),
        (NtStatus::INSUFFICIENT_RESOURCES, ErrorKind::Other),
        (NtStatus::INSUFF_SERVER_RESOURCES, ErrorKind::Other),
    ];

    #[test]
    fn classify_status_contract() {
        for (status, expected) in STATUS_CLASSIFICATION_CONTRACT {
            let err = Error::Protocol {
                status: *status,
                command: Command::Create,
            };
            assert_eq!(
                err.kind(),
                *expected,
                "{status} should classify as {expected:?}"
            );
        }
    }

    #[test]
    fn kind_maps_non_protocol_errors() {
        assert_eq!(Error::Timeout.kind(), ErrorKind::TimedOut);
        assert_eq!(Error::Disconnected.kind(), ErrorKind::ConnectionLost);
        assert_eq!(Error::Cancelled.kind(), ErrorKind::Cancelled);
        assert_eq!(Error::SessionExpired.kind(), ErrorKind::SessionExpired);
        assert_eq!(Error::invalid_data("test").kind(), ErrorKind::InvalidData);
        assert_eq!(
            Error::FileTooLargeForSingleRead {
                size: 20_000_000,
                max_read: 8_388_608,
            }
            .kind(),
            ErrorKind::TooLarge
        );
        assert!(
            !Error::FileTooLargeForSingleRead {
                size: 20_000_000,
                max_read: 8_388_608,
            }
            .is_retryable(),
            "too-large is not fixed by retrying the same call"
        );
        assert_eq!(
            Error::DfsReferralRequired {
                path: "test".into()
            }
            .kind(),
            ErrorKind::DfsReferral
        );
        assert_eq!(
            Error::Auth {
                message: "test".into()
            }
            .kind(),
            ErrorKind::AuthRequired
        );
    }

    #[test]
    fn kind_maps_io_error_to_io_not_connection_lost() {
        // Error::Io from callback errors (like write_file_streamed cancellation)
        // should NOT be ConnectionLost — the connection may still be usable.
        let err = Error::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "cancelled",
        ));
        assert_eq!(err.kind(), ErrorKind::Io);
        assert_ne!(err.kind(), ErrorKind::ConnectionLost);
    }

    #[test]
    fn kind_disconnected_is_connection_lost() {
        // Error::Disconnected (transport EOF) IS a connection loss.
        assert_eq!(Error::Disconnected.kind(), ErrorKind::ConnectionLost);
    }

    #[test]
    fn kind_maps_dfs_referral_required_to_dfs_referral() {
        // The explicit DFS referral error variant should also map to DfsReferral.
        let err = Error::DfsReferralRequired {
            path: r"\\server\share\path".into(),
        };
        assert_eq!(err.kind(), ErrorKind::DfsReferral);
    }

    #[test]
    fn dfs_referral_is_not_retryable() {
        // DFS referrals need special handling, not generic retry.
        let err = Error::Protocol {
            status: NtStatus::PATH_NOT_COVERED,
            command: Command::Create,
        };
        assert!(!err.is_retryable());
    }
}
