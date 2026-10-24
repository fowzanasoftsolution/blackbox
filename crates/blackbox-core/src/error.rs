//! Storage-core error type shared by the frame codec, segment engine, and queue actor.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupt frame at offset {offset}: {reason}")]
    Corrupt { offset: u64, reason: String },

    #[error("serialization/deserialization error: {0}")]
    Codec(String),

    #[error("embedded database error: {0}")]
    Db(String),

    #[error("queue actor is closed")]
    Closed,

    #[error("operation timed out after {0}ms")]
    Timeout(u64),
}

impl From<rkyv::rancor::Error> for StorageError {
    fn from(e: rkyv::rancor::Error) -> Self {
        StorageError::Codec(e.to_string())
    }
}

impl From<redb::Error> for StorageError {
    fn from(e: redb::Error) -> Self {
        StorageError::Db(e.to_string())
    }
}
