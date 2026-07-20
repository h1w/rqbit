# rqbit Tunnel Carrier Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the private BEP 52 carrier primitives and internal carrier state needed for a tunnel pair to exchange valid torrent pieces without registering a user-visible torrent.

**Architecture:** Keep v2 carrier metadata separate from the repository's current `TorrentMetaV1*` types. `librqbit_core` owns serializable, validated BEP 52 metadata and SHA-256/Merkle verification; `librqbit::tunnel::carrier` owns corpus persistence, bitfields, and piece serving. The carrier is internal to `TunnelService`, not `Session::db`.

**Tech Stack:** Rust 2024, existing bencode/buffers/bytes/bitvec/Tokio, `sha2` 0.10.9, existing `Id32` and `Id32::truncate_for_dht`.

## Global Constraints

- Use BEP 52 `meta version = 2`, SHA-256 info hashes, 16 KiB leaves, and valid piece layers.
- Do not modify `TorrentMetaV1*`, `create_torrent`, or ordinary torrent storage behavior in this plan.
- Internal carrier data must persist below the tunnel state directory, not a user torrent output folder.
- Metadata parsing must reject path traversal, invalid tree entries, invalid Merkle layer lengths, and mismatched piece roots.
- All tests use generated temporary corpus data; no tracker, DHT, or external network access.

---

### Task 1: Add BEP 52 metadata and validation primitives

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/librqbit_core/Cargo.toml`
- Modify: `crates/librqbit_core/src/lib.rs`
- Create: `crates/librqbit_core/src/torrent_metainfo_v2.rs`
- Test: inline tests in `crates/librqbit_core/src/torrent_metainfo_v2.rs`

**Interfaces:**
- Consumes: `Id32`, `Id20`, `ByteBuf`, `ByteBufOwned`, `bencode::WithRawBytes`.
- Produces: `TorrentMetaV2<Buf>`, `TorrentMetaV2Info<Buf>`, `ValidatedTorrentMetaV2Info<Buf>`, `V2File`, `PieceLayer`, `torrent_v2_from_bytes`, and `info_hash_v2`.

- [ ] **Step 1: Add the failing metadata tests**

Create tests for: a one-file v2 torrent whose SHA-256 info hash equals the hash of raw bencoded `info`; a two-file tree with 16 KiB leaves; rejection of `meta version != 2`; rejection of `..` path components; rejection of a piece-layer byte string whose length is not a multiple of 32.

```rust
#[test]
fn parses_v2_info_and_uses_sha256_raw_info_hash() {
    let torrent = torrent_v2_from_bytes(&fixture_bytes()).unwrap();
    assert_eq!(torrent.info.meta_version, 2);
    assert_eq!(torrent.info_hash, expected_info_hash());
    assert_eq!(torrent.handshake_info_hash(), torrent.info_hash.truncate_for_dht());
}

#[test]
fn rejects_piece_layer_with_non_hash_aligned_length() {
    assert!(matches!(
        torrent_v2_from_bytes(&invalid_piece_layer_fixture()),
        Err(Error::InvalidV2PieceLayerLength { .. })
    ));
}
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run:

```bash
cargo test -p librqbit-core torrent_metainfo_v2 -- --nocapture
```

Expected: compilation failure because the v2 module and parser do not exist.

- [ ] **Step 3: Add the minimal v2 data model and parser**

Add `sha2 = "0.10.9"` to workspace dependencies and `sha2.workspace = true` to `librqbit_core`. Add the module export in `lib.rs`.

Implement the following public boundary; use `WithRawBytes` so `info_hash_v2` hashes exactly the encoded `info` dictionary.

```rust
pub type TorrentMetaV2Owned = TorrentMetaV2<ByteBufOwned>;

pub struct TorrentMetaV2<Buf> {
    pub info: WithRawBytes<TorrentMetaV2Info<Buf>, Buf>,
    pub piece_layers: HashMap<Id32, Buf>,
    pub info_hash: Id32,
}

pub struct TorrentMetaV2Info<Buf> {
    pub meta_version: u64,
    pub piece_length: u32,
    pub file_tree: V2FileTree<Buf>,
    pub name: Option<Buf>,
    pub private: bool,
}

pub fn torrent_v2_from_bytes(buf: &[u8]) -> Result<TorrentMetaV2<ByteBuf<'_>>;

impl<Buf: AsRef<[u8]>> TorrentMetaV2Info<Buf> {
    pub fn validate(self, piece_layers: &HashMap<Id32, Buf>) -> Result<ValidatedTorrentMetaV2Info<Buf>>;
}
```

Use `sha2::Sha256` for the raw info hash. Require a power-of-two piece length of at least 16 KiB. Flatten the BEP 52 file tree into validated file records without accepting empty, `.` or `..` path elements. Verify that every non-empty file root has a matching layer only when its size requires one.

- [ ] **Step 4: Run the focused tests and verify they pass**

Run:

```bash
cargo test -p librqbit-core torrent_metainfo_v2 -- --nocapture
cargo fmt --all -- --check
```

Expected: metadata tests pass; formatter reports no diff.

- [ ] **Step 5: Commit the metadata primitive**

```bash
git add Cargo.toml crates/librqbit_core/Cargo.toml crates/librqbit_core/src/lib.rs crates/librqbit_core/src/torrent_metainfo_v2.rs
git commit -m "feat: add BEP52 tunnel carrier metadata"
```

### Task 2: Build and persist an internal v2 carrier corpus

**Files:**
- Modify: `crates/librqbit/src/lib.rs`
- Create: `crates/librqbit/src/tunnel/mod.rs`
- Create: `crates/librqbit/src/tunnel/carrier.rs`
- Test: inline tests in `crates/librqbit/src/tunnel/carrier.rs`

**Interfaces:**
- Consumes: `ValidatedTorrentMetaV2Info`, `Id32`, `BlockingSpawner`, `PathBuf`, and the existing filesystem APIs.
- Produces: `TunnelCarrier`, `TunnelCarrierDescriptor`, `TunnelCarrierStore`, and read-only piece APIs for the peer handler.

- [ ] **Step 1: Write failing corpus lifecycle tests**

Cover deterministic first initialization, reopening persisted state, a valid bitfield for the seeded corpus, and a failed read for an invalid piece index.

```rust
#[tokio::test]
async fn initializes_then_reopens_the_same_carrier() {
    let dir = tempfile::tempdir().unwrap();
    let first = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config()).await.unwrap();
    let descriptor = first.descriptor().clone();
    drop(first);

    let reopened = TunnelCarrierStore::open_or_initialize(dir.path(), &test_config()).await.unwrap();
    assert_eq!(reopened.descriptor(), &descriptor);
    assert!(reopened.have_bitfield().all());
}
```

- [ ] **Step 2: Run the carrier tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::carrier -- --nocapture
```

Expected: compilation failure because `tunnel::carrier` is absent.

- [ ] **Step 3: Implement the internal carrier store**

Expose the following interface from `tunnel::carrier` and keep it private to the `tunnel` module except for the descriptor used by pairing.

```rust
#[derive(Clone, Debug)]
pub(crate) struct TunnelCarrierConfig {
    pub corpus_bytes: u64,
    pub piece_length: u32,
    pub display_name: String,
}

pub(crate) struct TunnelCarrierStore {
    descriptor: TunnelCarrierDescriptor,
    root: PathBuf,
    have: BitBox<u8, Msb0>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelCarrierDescriptor {
    pub info_hash: Id32,
    pub handshake_info_hash: Id20,
    pub metainfo: Bytes,
}

impl TunnelCarrierStore {
    pub async fn open_or_initialize(root: &Path, config: &TunnelCarrierConfig) -> anyhow::Result<Self>;
    pub fn descriptor(&self) -> &TunnelCarrierDescriptor;
    pub fn have_bitfield(&self) -> &BitSlice<u8, Msb0>;
    pub async fn read_piece(&self, piece: ValidPieceIndex, out: &mut [u8]) -> anyhow::Result<()>;
}
```

Generate a persistent legal opaque corpus only when no descriptor exists. Serialize its v2 metainfo and write corpus plus descriptor atomically using a temporary path and rename. Reopen existing files only after re-validating metadata and every stored piece root. Do not use `Session::db`, `AddTorrent`, tracker, or DHT.

- [ ] **Step 4: Run the focused tests and verify persistence behavior**

Run:

```bash
cargo test -p librqbit tunnel::carrier -- --nocapture
cargo fmt --all -- --check
```

Expected: first-open/reopen, bitfield, and invalid-index tests pass.

- [ ] **Step 5: Commit carrier persistence**

```bash
git add crates/librqbit/src/lib.rs crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/carrier.rs
git commit -m "feat: add persistent tunnel carrier"
```

### Task 3: Add a carrier peer-state machine independent of normal torrents

**Files:**
- Create: `crates/librqbit/src/tunnel/carrier_peer.rs`
- Modify: `crates/librqbit/src/tunnel/mod.rs`
- Test: inline tests in `crates/librqbit/src/tunnel/carrier_peer.rs`

**Interfaces:**
- Consumes: `TunnelCarrierStore`, `Message`, `Request`, `Piece`, `ValidPieceIndex`.
- Produces: `TunnelCarrierPeer`, which handles valid bitfield, request, have, piece, choke, and interest transitions without `TorrentStateLive`.

- [ ] **Step 1: Write failing carrier peer tests**

Test that a peer with the descriptor sends a correctly sized bitfield, rejects a request outside the carrier length, serves a requested seeded block, and accepts only a piece matching the v2 Merkle root.

```rust
#[tokio::test]
async fn rejects_piece_whose_v2_root_does_not_match() {
    let mut peer = test_peer().await;
    let result = peer.on_piece(test_piece_with_byte_flipped()).await;
    assert!(matches!(result, Err(TunnelCarrierError::PieceHashMismatch { .. })));
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel::carrier_peer -- --nocapture
```

Expected: compilation failure because `TunnelCarrierPeer` is absent.

- [ ] **Step 3: Implement deterministic carrier message handling**

Implement a state machine with this boundary:

```rust
pub(crate) struct TunnelCarrierPeer {
    carrier: Arc<TunnelCarrierStore>,
    remote_have: BitBox<u8, Msb0>,
    local_choked: bool,
    remote_choked: bool,
}

impl TunnelCarrierPeer {
    pub fn initial_messages(&self) -> Vec<Message<'static>>;
    pub async fn on_message(&mut self, message: Message<'_>) -> Result<Vec<CarrierAction>, TunnelCarrierError>;
}
```

`CarrierAction` must be either a bounded outgoing peer-wire message or an explicit disconnect reason. Validate request indices, offsets, and lengths against carrier metadata before reading storage. Validate received piece blocks against the v2 leaf/root path before marking availability. Do not call `TorrentStateLive` methods or increment user torrent counters.

- [ ] **Step 4: Run the carrier foundation suite**

Run:

```bash
cargo test -p librqbit-core torrent_metainfo_v2 -- --nocapture
cargo test -p librqbit tunnel::carrier -- --nocapture
cargo test -p librqbit tunnel::carrier_peer -- --nocapture
```

Expected: all carrier metadata, persistence, and peer-state tests pass.

- [ ] **Step 5: Commit the independent carrier peer state**

```bash
git add crates/librqbit/src/tunnel/mod.rs crates/librqbit/src/tunnel/carrier_peer.rs
git commit -m "feat: add tunnel carrier peer state"
```
