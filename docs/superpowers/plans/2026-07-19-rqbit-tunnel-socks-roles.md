# rqbit Tunnel SOCKS Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `client` and `server` tunnel roles: a loopback SOCKS5 inbound on the desktop and an authenticated VPS egress relay connected only through the secure carrier transport.

**Architecture:** `TunnelOptions` is attached to `SessionOptions`, but `TunnelService` is separate from normal session torrents and starts its own listener/task lifecycle. Server mode admits only encrypted carrier peers matching the pairing bundle and static-key allowlist. Client mode parses SOCKS5 locally, turns requests into `TunnelFrame`s, and never opens the destination itself.

**Tech Stack:** Rust 2024, Tokio, existing `Session` cancellation/spawn conventions, `fast-socks5` 0.9.0, `TunnelConnection` and carrier interfaces from prior plans.

## Global Constraints

- Bind client SOCKS to loopback unless an explicit unsafe non-loopback option is later approved.
- Never call `DnsResolveHelper::resolve_dns()` on the client request path.
- Do not use `run_tcp_proxy` or `run_udp_proxy`; both create direct local upstream traffic.
- Server egress must enforce an allow/deny destination policy before DNS resolution and after resolved IP selection.
- Server listener is separate from `Session::check_incoming_connection`; tunnel peers must not be routed through `Session::db`.
- `TCPBind` is rejected with SOCKS `CommandNotSupported`.
- A peer disconnect closes active TCP streams and UDP associations; there is no direct or transparent failover path.

---

### Task 1: Add typed tunnel configuration and service lifecycle

**Files:**
- Modify: `crates/librqbit/Cargo.toml`
- Modify: `crates/librqbit/src/lib.rs`
- Modify: `crates/librqbit/src/session.rs`
- Create: `crates/librqbit/src/tunnel/options.rs`
- Create: `crates/librqbit/src/tunnel/service.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs`
- Test: inline tests in `options.rs` and `service.rs`

**Interfaces:**
- Consumes: `SessionOptions`, `CancellationToken`, `TunnelCarrierDescriptor`, `TunnelConnection`.
- Produces: public `TunnelOptions`, `TunnelMode`, `TunnelClientOptions`, `TunnelServerOptions`, and `TunnelService`.

- [ ] **Step 1: Write failing configuration validation tests**

Test client loopback default, rejection of missing pinned server key, rejection of server mode with an empty client allowlist, rejection of `client` mode without server endpoint, and that `SessionOptions::default()` starts no tunnel.

```rust
#[test]
fn client_mode_requires_server_address_and_pinned_key() {
    let options = TunnelOptions::Client(TunnelClientOptions::default());
    assert!(matches!(options.validate(), Err(TunnelConfigError::MissingServerAddress)));
}

#[tokio::test]
async fn default_session_starts_without_tunnel_service() {
    let session = Session::new_with_opts(tempdir_path(), SessionOptions::default()).await.unwrap();
    assert!(session.tunnel_service().is_none());
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::options -- --nocapture
cargo test -p librqbit tunnel::service -- --nocapture
```

Expected: compilation failure because tunnel options and service are absent.

- [ ] **Step 3: Implement options and service startup**

Add `fast-socks5 = "0.9.0"` to workspace dependencies and make it available to `librqbit`. Add `pub tunnel: Option<TunnelOptions>` to `SessionOptions`; retain `None` in its default implementation. Expose a read-only accessor, not mutable session state.

```rust
#[derive(Clone, Debug)]
pub enum TunnelOptions {
    Client(TunnelClientOptions),
    Server(TunnelServerOptions),
}

#[derive(Clone, Debug)]
pub struct TunnelClientOptions {
    pub socks_listen: SocketAddr,
    pub server_addr: SocketAddr,
    pub identity_key: TunnelPrivateKey,
    pub expected_server_key: TunnelPublicKey,
    pub pairing: TunnelPairingBundle,
}

#[derive(Clone, Debug)]
pub struct TunnelServerOptions {
    pub peer_listen: SocketAddr,
    pub identity_key: TunnelPrivateKey,
    pub allowed_client_keys: HashSet<TunnelPublicKey>,
    pub egress_policy: EgressPolicy,
    pub carrier_root: PathBuf,
}

pub struct TunnelService;

impl TunnelService {
    pub async fn start(session: &Arc<Session>, options: TunnelOptions) -> anyhow::Result<Arc<Self>>;
    pub async fn shutdown(&self);
}
```

Start `TunnelService` only after the `Arc<Session>` exists and use its child cancellation token. Store it outside `SessionDatabase`; use an `ArcSwapOption<TunnelService>` or an immutable `Option<Arc<TunnelService>>` set during construction. Do not reuse regular listener sockets or `Session::task_listener`.

- [ ] **Step 4: Run configuration and lifecycle tests**

Run:

```bash
cargo test -p librqbit tunnel::options -- --nocapture
cargo test -p librqbit tunnel::service -- --nocapture
cargo fmt --all -- --check
```

Expected: validation and default-no-tunnel tests pass.

- [ ] **Step 5: Commit role configuration**

```bash
git add Cargo.toml crates/librqbit/Cargo.toml crates/librqbit/src/lib.rs crates/librqbit/src/session.rs crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/options.rs crates/librqbit/src/tunnel/service.rs
git commit -m "feat: add tunnel role configuration"
```

### Task 2: Implement authenticated server admission and egress

**Files:**
- Create: `crates/librqbit/src/tunnel/server.rs`
- Create: `crates/librqbit/src/tunnel/egress.rs`
- Modify: `crates/librqbit/src/tunnel/service.rs`
- Test: inline tests in `server.rs` and `egress.rs`

**Interfaces:**
- Consumes: `TunnelServerOptions`, `PeerWireCrypto`, `TunnelCarrierStore`, `TunnelConnection`.
- Produces: `TunnelServer`, `EgressPolicy`, `EgressTcp`, and `EgressUdpAssociation`.

- [ ] **Step 1: Write failing server admission and policy tests**

Cover rejection before the carrier session for an unpaired infohash, rejection of a Noise-authenticated but non-allowlisted client key, allowed TCP to a permitted loopback echo server, denied port, denied resolved IP range, and UDP association expiry.

```rust
#[tokio::test]
async fn server_rejects_unknown_client_after_static_key_handshake() {
    let server = test_server(allowed_client_keys(&[known_key()]));
    let result = server.accept(test_peer_for(unknown_key())).await;
    assert!(matches!(result, Err(TunnelAdmissionError::ClientNotAllowed(_))));
}

#[tokio::test]
async fn egress_policy_denies_resolved_private_address() {
    let policy = EgressPolicy::public_internet_only();
    assert!(matches!(policy.check_resolved("example.test", private_ip(), 443), Err(EgressError::DestinationDenied)));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::server -- --nocapture
cargo test -p librqbit tunnel::egress -- --nocapture
```

Expected: compilation failure because admission and egress modules are absent.

- [ ] **Step 3: Implement server listener, pairing validation, and egress handles**

Bind a dedicated TCP listener and optional uTP listener from `TunnelServerOptions::peer_listen`. For each accepted stream: run `PeerWireCrypto::responder`, parse the standard carrier handshake, require the pairing descriptor's truncated carrier hash, complete the typed extension/Noise handshake, then verify the client public key allowlist.

```rust
pub enum EgressTransport { Tcp, Udp }

pub struct ResolvedDestination {
    pub requested: TunnelDestination,
    pub selected: SocketAddr,
}

pub enum EgressError {
    DestinationDenied,
    Resolve(anyhow::Error),
    Connect(std::io::Error),
    TimedOut,
}

pub struct EgressPolicy {
    pub allowed_tcp_ports: Vec<std::ops::RangeInclusive<u16>>,
    pub allowed_udp_ports: Vec<std::ops::RangeInclusive<u16>>,
    pub denied_networks: IpRanges,
    pub max_tcp_streams_per_client: usize,
    pub max_udp_associations_per_client: usize,
    pub idle_timeout: Duration,
}

impl EgressPolicy {
    pub async fn authorize(&self, destination: &TunnelDestination, transport: EgressTransport) -> Result<ResolvedDestination, EgressError>;
}
```

Resolve hostnames only on the server. Apply hostname rules before resolution and IP/CIDR rules after resolution. Map policy, DNS, connect, and timeout errors to `TunnelErrorCode` values that client SOCKS code can map to RFC 1928 replies. Track every open TCP stream and UDP association by authenticated client key plus frame identifier.

- [ ] **Step 4: Run server and egress tests**

Run:

```bash
cargo test -p librqbit tunnel::server -- --nocapture
cargo test -p librqbit tunnel::egress -- --nocapture
```

Expected: all admission, destination policy, and timeout tests pass.

- [ ] **Step 5: Commit server relay mode**

```bash
git add crates/librqbit/src/tunnel/service.rs crates/librqbit/src/tunnel/server.rs crates/librqbit/src/tunnel/egress.rs
git commit -m "feat: add tunnel server relay"
```

### Task 3: Implement client SOCKS5 CONNECT and UDP ASSOCIATE

**Files:**
- Create: `crates/librqbit/src/tunnel/client.rs`
- Create: `crates/librqbit/src/tunnel/socks.rs`
- Create: `crates/librqbit/src/tunnel/socks_udp.rs`
- Modify: `crates/librqbit/src/tunnel/service.rs`
- Test: inline tests in `client.rs`, `socks.rs`, and `socks_udp.rs`

**Interfaces:**
- Consumes: `TunnelClientOptions`, `TunnelConnection`, `fast_socks5::server::Socks5ServerProtocol`.
- Produces: `TunnelClient`, `SocksIngress`, and RFC 1928 UDP encapsulation functions.

- [ ] **Step 1: Write failing SOCKS behavior tests**

Test local CONNECT through an in-process authenticated tunnel pair into a TCP echo server; a domain destination remains a `TunnelDestination::Domain` at the client; `TCPBind` returns command-not-supported; SOCKS UDP encapsulation round-trips IPv4, IPv6, and domain addresses; malformed UDP fragment values are rejected; TCP control close removes the UDP association.

```rust
#[tokio::test]
async fn client_never_resolves_a_domain_before_tunnel_open() {
    let client = test_client().await;
    client.open_tcp(TunnelDestination::Domain("example.test".into(), 443)).await.unwrap();
    assert_eq!(client.sent_open().destination, TunnelDestination::Domain("example.test".into(), 443));
    assert_eq!(client.local_resolver_calls(), 0);
}

#[test]
fn rejects_fragmented_socks_udp_datagrams() {
    assert!(matches!(parse_socks_udp_datagram(&[0, 0, 1, 1]), Err(SocksUdpError::FragmentationUnsupported)));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::client -- --nocapture
cargo test -p librqbit tunnel::socks -- --nocapture
cargo test -p librqbit tunnel::socks_udp -- --nocapture
```

Expected: compilation failure because client/SOCKS modules are absent.

- [ ] **Step 3: Implement manual SOCKS control and UDP encapsulation**

Use `Socks5ServerProtocol::accept_no_auth` and `read_command()` without `resolve_dns()`. For `TCPConnect`, hold the returned stream after `reply_success`, register its stream ID, and transfer bytes only through `TunnelConnection`. For `UDPAssociate`, bind a loopback UDP socket, reply with that socket address, parse and emit RFC 1928 UDP request headers, and keep the control TCP connection alive until association shutdown.

```rust
pub(crate) enum SocksCommandResult {
    Tcp { stream_id: u64 },
    Udp { association_id: u64, relay_addr: SocketAddr },
}

pub(crate) fn parse_socks_udp_datagram(input: &[u8]) -> Result<(TunnelDestination, &[u8]), SocksUdpError>;
pub(crate) fn encode_socks_udp_datagram(source: &TunnelDestination, payload: &[u8], out: &mut Vec<u8>);
```

Reject `TCPBind`, SOCKS UDP fragmentation (`FRAG != 0`), datagrams exceeding tunnel policy, and any destination that the server rejects. On tunnel peer loss, reply/close the local stream or association; never connect the client machine directly to the destination.

- [ ] **Step 4: Run the role-focused test suite**

Run:

```bash
cargo test -p librqbit tunnel::client -- --nocapture
cargo test -p librqbit tunnel::socks -- --nocapture
cargo test -p librqbit tunnel::socks_udp -- --nocapture
cargo fmt --all -- --check
```

Expected: TCP, domain, UDP, malformed-header, and no-direct-fallback tests pass.

- [ ] **Step 5: Commit client SOCKS mode**

```bash
git add crates/librqbit/src/tunnel/service.rs crates/librqbit/src/tunnel/client.rs crates/librqbit/src/tunnel/socks.rs crates/librqbit/src/tunnel/socks_udp.rs
git commit -m "feat: add tunnel client socks ingress"
```
