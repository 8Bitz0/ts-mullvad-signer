mod lock;

pub use lock::{LockStatus, sign_node};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error fetching lock status: {0}")]
    FetchLockStatus(#[source] std::io::Error),
    #[error("Error reading output for Tailscale subprocess: {0}")]
    ReadSubprocessOutput(#[source] std::str::Utf8Error),
    #[error("Error parsing Tailscale output: {0}")]
    ParseOutput(#[source] serde_json::Error),
    #[error("Error signing node: {0}")]
    SignNode(#[source] std::io::Error),
}
