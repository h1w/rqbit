// ── Tunnel service lifecycle ────────────────────────────────────────────────
//
// A TunnelService owns the long-running tasks needed for a tunnel endpoint:
//   - Client: SOCKS5 → tunnel → server
//   - Server: listen for tunnel peers → relay frames
//
// The service is started during Session construction via
// `TunnelService::start()` and shut down when the session cancellation token
// is triggered.

use std::sync::Arc;

use crate::session::Session;

use super::options::TunnelOptions;

/// Handle to a running tunnel service.
///
/// Created by [`TunnelService::start`] and stored on [`Session`].  When the
/// session's cancellation token fires (or [`shutdown`](Self::shutdown) is
/// called explicitly) the background tasks are torn down.
pub struct TunnelService;

impl TunnelService {
    /// Start the tunnel service for the given session and configuration.
    ///
    /// The configuration is validated before any resources are allocated.
    /// Background tasks are spawned on the session's child cancellation token
    /// so they are torn down when the session stops.
    pub async fn start(
        _session: &Arc<Session>,
        options: TunnelOptions,
    ) -> anyhow::Result<Arc<Self>> {
        options.validate()?;
        // TODO: actual tunnel startup (SOCKS listener, peer listener, relay tasks)
        // will be wired in follow-up tasks.
        Ok(Arc::new(Self))
    }

    /// Initiate graceful shutdown of the tunnel service.
    ///
    /// Currently a no-op — background tasks are torn down by the cancellation
    /// token.
    pub async fn shutdown(&self) {
        // TODO: signal background tasks before token fires
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;

    use super::super::frame::{TunnelPrivateKey, TunnelPublicKey};
    use super::super::options::{
        EgressPolicy, TunnelClientOptions, TunnelOptions, TunnelServerOptions,
    };

    fn dummy_key() -> TunnelPublicKey {
        let mut key = [0u8; 32];
        key[0] = 1;
        TunnelPublicKey(key)
    }

    fn dummy_private() -> TunnelPrivateKey {
        let mut key = [0u8; 32];
        key[0] = 1;
        TunnelPrivateKey(key)
    }

    #[tokio::test]
    async fn start_client_with_valid_config() {
        let opts = TunnelOptions::Client(TunnelClientOptions {
            server_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9090)),
            expected_server_key: dummy_key(),
            ..Default::default()
        });

        // Without a real Session we just verify the validate path.
        assert!(opts.validate().is_ok());
    }

    #[tokio::test]
    async fn start_server_with_valid_config() {
        let mut allowed = std::collections::HashSet::new();
        allowed.insert(dummy_key());
        let opts = TunnelOptions::Server(TunnelServerOptions {
            peer_listen: SocketAddr::from(([0, 0, 0, 0], 9091)),
            identity_key: dummy_private(),
            allowed_client_keys: allowed,
            egress_policy: EgressPolicy::default(),
            carrier_root: PathBuf::from("/tmp"),
        });

        assert!(opts.validate().is_ok());
    }

    #[tokio::test]
    async fn default_session_starts_without_tunnel_service() {
        let dir = tempfile::tempdir().unwrap();
        let session = crate::session::Session::new_with_opts(
            dir.path().to_path_buf(),
            crate::session::SessionOptions::default(),
        )
        .await
        .unwrap();
        assert!(session.tunnel_service().is_none());
    }
}
