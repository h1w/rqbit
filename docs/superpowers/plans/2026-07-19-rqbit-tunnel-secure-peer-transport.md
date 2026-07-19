# rqbit Tunnel Secure Peer Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add encrypted peer-wire setup, a negotiated typed `rq_tunnel` extension, and static-key authenticated encrypted frames for the internal carrier connection.

**Architecture:** The outer transport wrapper is responsible for BitTorrent peer-wire encryption/obfuscation before the current handshake parser consumes bytes. The inner `Noise_IK_25519_ChaChaPoly_SHA256` session authenticates client and server identities and encrypts every tunnel frame. `peer_binary_protocol` gains a bounded raw extension variant; `librqbit::tunnel` owns framing, flow control, and key lifecycle.

**Tech Stack:** Rust 2024, existing `sha1w`, `peer_binary_protocol`, Tokio, `rc4` 0.1.0, `num-bigint` 0.4.6, `snow` 0.9.6.

## Global Constraints

- Outer peer-wire encryption is mandatory for tunnel client/server connections; do not negotiate plaintext fallback.
- Inner Noise transport is mandatory after extended-message negotiation; reject a connection if static-key authentication fails.
- Use `Noise_IK_25519_ChaChaPoly_SHA256`: client pins the server static public key; server reads and allowlists the client static public key from the authenticated handshake.
- Do not invent cryptographic primitives, derive ad hoc keys, reuse nonces, or log secret material.
- Tunnel queues are bounded; no path may use the existing unbounded torrent writer queue for unbounded tunnel data.
- Raw extension payloads are capped below the peer-wire buffer limit and reject oversized input before allocation.

---

### Task 1: Implement the peer-wire encryption handshake wrapper

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/librqbit/Cargo.toml`
- Create: `crates/librqbit/src/tunnel/peer_wire_crypto.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs`
- Test: inline tests in `crates/librqbit/src/tunnel/peer_wire_crypto.rs`

**Interfaces:**
- Consumes: `Id20` carrier handshake hash, Tokio `AsyncRead`/`AsyncWrite`, and the tunnel role.
- Produces: encrypted reader/writer halves implementing the existing vectored read/write traits.

- [ ] **Step 1: Write failing handshake tests**

Cover client/server round-trip after negotiated encryption, rejection of plaintext selection, invalid Diffie-Hellman public value, truncated padding, mismatched carrier handshake hash, and byte-for-byte recovery of a standard BitTorrent handshake through the wrapper.

```rust
#[tokio::test]
async fn requires_encrypted_peer_wire_and_recovers_handshake_bytes() {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let carrier_hash = Id20::new([7; 20]);
    let (client, server) = tokio::join!(
        PeerWireCrypto::initiator(client_io, carrier_hash),
        PeerWireCrypto::responder(server_io, carrier_hash),
    );
    let (mut client_read, mut client_write) = client.unwrap();
    let (mut server_read, mut server_write) = server.unwrap();
    client_write.write_all(b"BitTorrent protocol").await.unwrap();
    let mut plain = [0; 18];
    server_read.read_exact(&mut plain).await.unwrap();
    assert_eq!(&plain, b"BitTorrent protocol");
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::peer_wire_crypto -- --nocapture
```

Expected: compilation failure because the peer-wire crypto module does not exist.

- [ ] **Step 3: Implement the MSE/PE state machine**

Add `rc4 = "0.1.0"` and `num-bigint = "0.4.6"` to workspace dependencies and make them available only to `librqbit`'s tunnel feature. Implement the published MSE state machine in `PeerWireCrypto`:

```rust
pub(crate) enum PeerWireCryptoRole { Initiator, Responder }

pub(crate) struct EncryptedPeerIo {
    pub reader: BoxAsyncReadVectored,
    pub writer: BoxAsyncWrite,
}

pub(crate) struct PeerWireCrypto;

impl PeerWireCrypto {
    pub async fn initiator<S>(stream: S, carrier_hash: Id20) -> Result<EncryptedPeerIo, TunnelCryptoError>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    pub async fn responder<S>(stream: S, expected_carrier_hash: Id20) -> Result<EncryptedPeerIo, TunnelCryptoError>
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static;
}
```

Use the MSE Diffie-Hellman group, validate received public values, calculate `req1`/`req2`/`req3` and directional keys from the carrier `Id20`, discard the first 1024 RC4 bytes in both directions, accept only encrypted selection, and bound every padding length before reading it. Wrap decrypted reads with `AsyncReadVectoredIntoCompat` so downstream `ReadBuf` remains unchanged.

- [ ] **Step 4: Run focused crypto tests and formatter**

Run:

```bash
cargo test -p librqbit tunnel::peer_wire_crypto -- --nocapture
cargo fmt --all -- --check
```

Expected: all malformed-handshake and encrypted-round-trip cases pass.

- [ ] **Step 5: Commit the peer-wire crypto wrapper**

```bash
git add Cargo.toml crates/librqbit/Cargo.toml crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/peer_wire_crypto.rs
git commit -m "feat: add encrypted tunnel peer wire"
```

### Task 2: Add the typed `rq_tunnel` extension message

**Files:**
- Modify: `crates/peer_binary_protocol/src/lib.rs`
- Modify: `crates/peer_binary_protocol/src/extended/mod.rs`
- Modify: `crates/peer_binary_protocol/src/extended/handshake.rs`
- Create: `crates/peer_binary_protocol/src/extended/rq_tunnel.rs`
- Test: inline tests in `crates/peer_binary_protocol/src/extended/rq_tunnel.rs` and `extended/mod.rs`

**Interfaces:**
- Consumes: BEP 10 peer extension ID negotiation.
- Produces: `ExtendedMessage::RqTunnel`, `PeerExtendedMessageIds::rq_tunnel`, and `RqTunnelMessage`.

- [ ] **Step 1: Write failing extension negotiation tests**

Test that the local extended handshake advertises `rq_tunnel`, a peer-specific remote ID is used for outgoing messages, unknown IDs continue to decode as `Dyn`, oversized raw payloads are rejected, and a split receive buffer round-trips a valid raw payload.

```rust
#[test]
fn uses_the_remote_rq_tunnel_id_for_outgoing_payload() {
    let ids = PeerExtendedMessageIds { rq_tunnel: Some(9), ..Default::default() };
    let message = Message::Extended(ExtendedMessage::RqTunnel(RqTunnelMessage::from_bytes(b"abc")));
    let mut out = [0; 64];
    let written = message.serialize(&mut out, &|| ids).unwrap();
    assert_eq!(out[5], 9);
    assert_eq!(&out[6..written], b"abc");
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit-peer-protocol rq_tunnel -- --nocapture
```

Expected: compilation failure because `RqTunnelMessage` and the extension ID are absent.

- [ ] **Step 3: Implement bounded raw extension payload support**

Reserve a stable local extension ID and name `rq_tunnel`. Extend the handshake map and typed outgoing-ID lookup. The extension message payload is raw bytes after its extension ID, not bencode; require a named `MAX_RQ_TUNNEL_MESSAGE_LEN` below `MAX_MSG_LEN`.

```rust
pub const EXTENDED_RQ_TUNNEL_KEY: &[u8] = b"rq_tunnel";
pub const MY_EXTENDED_RQ_TUNNEL: u8 = 4;
pub const MAX_RQ_TUNNEL_MESSAGE_LEN: usize = 16 * 1024;

pub struct RqTunnelMessage<B>(B);

impl<'a> RqTunnelMessage<ByteBuf<'a>> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self;
    pub fn as_bytes(&self) -> &'a [u8];
}
```

Deserialize the message as raw bytes only when its incoming ID equals `MY_EXTENDED_RQ_TUNNEL`; retain current bencode `Dyn` behavior for every other unknown extension.

- [ ] **Step 4: Run protocol regression tests**

Run:

```bash
cargo test -p librqbit-peer-protocol -- --nocapture
```

Expected: all existing handshake, metadata, PEX, and new tunnel-extension tests pass.

- [ ] **Step 5: Commit the typed extension**

```bash
git add crates/peer_binary_protocol/src/lib.rs crates/peer_binary_protocol/src/extended/mod.rs crates/peer_binary_protocol/src/extended/handshake.rs crates/peer_binary_protocol/src/extended/rq_tunnel.rs
git commit -m "feat: add rq tunnel peer extension"
```

### Task 3: Add static-key authenticated tunnel frames

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/librqbit/Cargo.toml`
- Create: `crates/librqbit/src/tunnel/crypto.rs`
- Create: `crates/librqbit/src/tunnel/frame.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs`
- Test: inline tests in `crypto.rs` and `frame.rs`

**Interfaces:**
- Consumes: raw `RqTunnelMessage` payloads and configured static keys.
- Produces: encrypted `TunnelFrame` messages after a completed Noise IK handshake.

- [ ] **Step 1: Write failing authenticated-frame tests**

Cover server-key pinning, server allowlist acceptance/rejection of a client key, tampered ciphertext rejection, replay rejection, oversized plaintext rejection, and a TCP-open frame round trip.

```rust
#[test]
fn rejects_a_client_not_in_the_server_allowlist() {
    let result = complete_handshake(&unknown_client_key(), &server_keys(), &allowed_clients());
    assert!(matches!(result, Err(TunnelCryptoError::ClientNotAllowed(_))));
}

#[test]
fn encrypted_frame_round_trips_without_exposing_destination() {
    let (mut client, mut server) = authenticated_pair();
    let ciphertext = client.encrypt(&TunnelFrame::OpenTcp { stream_id: 1, host: "example.test".into(), port: 443 }).unwrap();
    assert!(!ciphertext.windows(b"example.test".len()).any(|w| w == b"example.test"));
    assert!(matches!(server.decrypt(&ciphertext).unwrap(), TunnelFrame::OpenTcp { stream_id: 1, .. }));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::crypto -- --nocapture
cargo test -p librqbit tunnel::frame -- --nocapture
```

Expected: compilation failure because the crypto and frame modules do not exist.

- [ ] **Step 3: Implement canonical frames and Noise IK transport**

Add `snow = "0.9.6"` to workspace and `snow.workspace = true` to `librqbit`. Define a canonical binary frame encoding with a version byte, type byte, connection/association identifier, payload length, and payload. Reject unknown versions and lengths before allocation.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelPrivateKey(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelPublicKey(pub [u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelPairingBundle {
    pub carrier: TunnelCarrierDescriptor,
    pub server_addr: SocketAddr,
    pub server_public_key: TunnelPublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelDestination {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelErrorCode {
    DestinationDenied,
    HostUnreachable,
    ConnectionRefused,
    TimedOut,
    PeerDisconnected,
    ProtocolViolation,
}

pub enum TunnelFrame {
    ClientHello(Vec<u8>),
    ServerHello(Vec<u8>),
    OpenTcp { stream_id: u64, host: String, port: u16 },
    TcpOpened { stream_id: u64, bind_addr: SocketAddr },
    TcpData { stream_id: u64, bytes: Bytes },
    TcpFin { stream_id: u64 },
    TcpReset { stream_id: u64, code: TunnelErrorCode },
    OpenUdp { association_id: u64 },
    UdpDatagram { association_id: u64, destination: TunnelDestination, bytes: Bytes },
    CloseUdp { association_id: u64 },
    Credit { stream_id: u64, bytes: u32 },
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}
```

Build the initiator with its local static private key and pinned server public key. Build the responder with its local static private key, inspect the authenticated remote static key after handshake, and reject keys absent from the allowlist. Convert to `TransportState` only after the complete IK handshake. Serialize each encrypted result into one bounded `RqTunnelMessage`; include monotonically increasing frame sequence numbers in the authenticated plaintext and reject duplicates or gaps.

- [ ] **Step 4: Run crypto/frame tests and formatter**

Run:

```bash
cargo test -p librqbit tunnel::crypto -- --nocapture
cargo test -p librqbit tunnel::frame -- --nocapture
cargo fmt --all -- --check
```

Expected: authentication, tamper, replay, and frame round-trip tests pass.

- [ ] **Step 5: Commit authenticated frames**

```bash
git add Cargo.toml crates/librqbit/Cargo.toml crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/crypto.rs crates/librqbit/src/tunnel/frame.rs
git commit -m "feat: add authenticated tunnel frames"
```

### Task 4: Couple bounded tunnel frames to a carrier connection

**Files:**
- Create: `crates/librqbit/src/tunnel/connection.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs`
- Test: inline tests in `crates/librqbit/src/tunnel/connection.rs`

**Interfaces:**
- Consumes: `EncryptedPeerIo`, `TunnelCarrierPeer`, `TunnelCryptoSession`, `RqTunnelMessage`.
- Produces: `TunnelConnection`, a cancellation-aware bounded request/response multiplexer.

- [ ] **Step 1: Write failing flow-control and disconnect tests**

```rust
#[tokio::test]
async fn full_outbound_queue_backpressures_instead_of_growing() {
    let connection = test_connection_with_capacity(1).await;
    connection.send(test_tcp_data(1, b"a")).await.unwrap();
    assert!(matches!(connection.try_send(test_tcp_data(1, b"b")), Err(TunnelSendError::Backpressured)));
}

#[tokio::test]
async fn peer_disconnect_fails_every_open_stream() {
    let connection = test_connection_with_open_streams(&[1, 2]).await;
    connection.on_peer_disconnect().await;
    assert_eq!(connection.stream_error(1), Some(TunnelErrorCode::PeerDisconnected));
    assert_eq!(connection.stream_error(2), Some(TunnelErrorCode::PeerDisconnected));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::connection -- --nocapture
```

Expected: compilation failure because `TunnelConnection` is absent.

- [ ] **Step 3: Implement the bounded multiplexer**

Use a bounded `tokio::sync::mpsc::channel`, a per-stream credit counter, and the session cancellation token. Give the writer task exclusive ownership of the encrypted peer writer. Dispatch ordinary carrier actions and `RqTunnelMessage` writes through the same serialized writer without placing arbitrary tunnel bytes in `WriterRequest`'s existing unbounded channel.

```rust
pub(crate) struct TunnelConnection {
    outbound: mpsc::Sender<TunnelFrame>,
    streams: DashMap<u64, StreamState>,
    cancellation: CancellationToken,
}

impl TunnelConnection {
    pub async fn send(&self, frame: TunnelFrame) -> Result<(), TunnelSendError>;
    pub fn try_send(&self, frame: TunnelFrame) -> Result<(), TunnelSendError>;
    pub async fn close(&self, reason: TunnelErrorCode);
}
```

On peer loss, close all stream and UDP association state with `PeerDisconnected`; never reconnect an existing TCP stream transparently.

- [ ] **Step 4: Run the secure transport suite**

Run:

```bash
cargo test -p librqbit-peer-protocol -- --nocapture
cargo test -p librqbit tunnel::peer_wire_crypto -- --nocapture
cargo test -p librqbit tunnel::crypto -- --nocapture
cargo test -p librqbit tunnel::connection -- --nocapture
```

Expected: protocol, crypto, framing, flow-control, and disconnect tests pass.

- [ ] **Step 5: Commit carrier/tunnel connection coupling**

```bash
git add crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/connection.rs
git commit -m "feat: add bounded tunnel connection"
```
