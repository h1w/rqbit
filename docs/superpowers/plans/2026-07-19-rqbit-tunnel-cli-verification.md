# rqbit Tunnel CLI and Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the approved tunnel roles through the `rqbit` binary and prove the client/server path, normal torrent regression, plaintext exclusion, and carrier trace contract end to end.

**Architecture:** CLI maps role-specific flags into `librqbit::TunnelOptions`; it does not create a second configuration model. Test-only capture wrappers record the raw client-to-VPS byte stream before decryption and normalized carrier-message traces after parsing. They prove defined invariants without claiming universal DPI immunity.

**Tech Stack:** Rust 2024, Clap 4, Tokio, existing `librqbit` tests, `tempfile`, existing test utilities.

## Global Constraints

- Do not add Web UI or HTTP API tunnel controls in this plan.
- Keep all existing CLI flags and their meanings unchanged.
- Do not overload `--socks-url`; tunnel client uses a new local SOCKS inbound flag.
- Server private keys and pairing bundles are file paths, never literal command-line secret values.
- Test captures must never be printed to logs or persisted outside test temporary directories.
- Validation commands include existing focused tests before workspace-wide checks.

---

### Task 1: Add role-specific CLI flags and mapping

**Files:**
- Modify: `crates/rqbit/src/main.rs`
- Test: inline tests in `crates/rqbit/src/main.rs`

**Interfaces:**
- Consumes: public `TunnelOptions`, `TunnelClientOptions`, `TunnelServerOptions` from `librqbit`.
- Produces: parsed tunnel configuration passed exactly once into `SessionOptions::tunnel`.

- [ ] **Step 1: Write failing CLI parsing tests**

Test a client invocation with local SOCKS address, VPS address, identity-key path, server-key path, and pairing-bundle path; test server invocation with peer listener, identity-key path, allowed-client-key file, carrier root, and policy file; test invalid mixed client/server flags; test that omitted tunnel flags leave `SessionOptions::tunnel == None`.

```rust
#[test]
fn parses_tunnel_client_without_reusing_outgoing_socks_proxy() {
    let opts = Opts::try_parse_from([
        "rqbit", "server", "start", "/tmp/data",
        "--tunnel-mode", "client",
        "--tunnel-socks-listen", "127.0.0.1:1080",
        "--tunnel-server-addr", "203.0.113.10:4242",
        "--tunnel-client-key", "/tmp/client.key",
        "--tunnel-server-key", "/tmp/server.pub",
        "--tunnel-pairing", "/tmp/pairing.bin",
    ]).unwrap();
    assert!(opts.socks_url.is_none());
    assert_eq!(opts.tunnel_mode, Some(TunnelRole::Client));
}
```

- [ ] **Step 2: Run the CLI tests and confirm they fail**

Run:

```bash
cargo test -p rqbit tunnel_ -- --nocapture
```

Expected: compilation failure because tunnel CLI fields are absent.

- [ ] **Step 3: Implement CLI fields and configuration loading**

Add a Clap `ValueEnum` with `Client` and `Server`, plus these role-specific flags:

```text
--tunnel-mode
--tunnel-socks-listen
--tunnel-server-addr
--tunnel-peer-listen
--tunnel-client-key
--tunnel-server-key
--tunnel-allowed-clients
--tunnel-pairing
--tunnel-carrier-root
--tunnel-egress-policy
```

Use `RQBIT_TUNNEL_*` environment variables matching each flag. Parse socket addresses with Clap's existing typed parser. Load identity and public-key material from files with strict permission/length validation, and load pairing/policy files before `Session::new_with_opts`. Reject all role-inapplicable flags with an error naming the flag and selected mode. Set `SessionOptions::tunnel` exactly once beside the existing `connect` construction.

- [ ] **Step 4: Run CLI tests and help output check**

Run:

```bash
cargo test -p rqbit tunnel_ -- --nocapture
cargo run -p rqbit -- server start --help
```

Expected: parsing tests pass and help shows a distinct tunnel section without changing `--socks-url` text.

- [ ] **Step 5: Commit CLI configuration**

```bash
git add crates/rqbit/src/main.rs
git commit -m "feat: add tunnel client and server CLI options"
```

### Task 2: Add end-to-end client/server SOCKS tests

**Files:**
- Create: `crates/librqbit/src/tests/tunnel.rs`
- Modify: `crates/librqbit/src/tests/mod.rs`
- Modify: `crates/librqbit/src/tests/test_util.rs`

**Interfaces:**
- Consumes: public `SessionOptions::tunnel` and the client/server option builders.
- Produces: hermetic two-node tunnel fixtures, TCP/UDP echo fixtures, and direct-fallback detection.

- [ ] **Step 1: Write the failing end-to-end tests**

Create a temporary VPS server session and desktop client session with independent carrier roots and a generated pairing bundle. Start a TCP echo service and UDP echo service only on the server-side test network. Cover TCP CONNECT, domain destination remote resolution, UDP ASSOCIATE, denied destination, wrong server key, unknown client key, peer loss, and no direct destination connection from the client.

```rust
#[tokio::test(flavor = "multi_thread")]
async fn socks_connect_reaches_server_side_tcp_echo_only_through_tunnel() {
    let fixture = TunnelFixture::start().await;
    let mut socks = fixture.client_socks().connect().await;
    socks.connect("echo.tunnel.test", fixture.tcp_echo_port()).await.unwrap();
    socks.write_all(b"hello").await.unwrap();
    assert_eq!(socks.read_exact_vec(5).await.unwrap(), b"hello");
    assert_eq!(fixture.client_direct_connect_attempts(), 0);
}
```

```rust
#[tokio::test(flavor = "multi_thread")]
async fn ordinary_torrent_still_downloads_while_client_tunnel_is_active() {
    let fixture = TunnelFixture::start().await;
    fixture.send_socks_payload(b"keep tunnel active").await;
    fixture.download_regular_test_torrent().await.unwrap();
    assert!(fixture.regular_torrent_completed());
}
```

- [ ] **Step 2: Run the end-to-end tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel_e2e -- --nocapture
```

Expected: compilation failure because tunnel test fixtures and roles are absent.

- [ ] **Step 3: Implement deterministic tunnel test fixtures**

Add `TunnelFixture` to `test_util.rs`. It must create all key files, pairing material, carrier roots, TCP/UDP echo listeners, and session cancellation tokens in a `TempDir`. Use a test-only resolver injected into server egress policy so `echo.tunnel.test` resolves only in the VPS fixture. Record attempted client TCP/UDP destination dials and fail the test if any occur outside the tunnel peer address.

- [ ] **Step 4: Run the end-to-end suite**

Run:

```bash
cargo test -p librqbit tunnel_e2e -- --nocapture
```

Expected: CONNECT, UDP, remote-DNS, rejection, disconnect, and no-direct-fallback tests pass.

- [ ] **Step 5: Commit end-to-end role tests**

```bash
git add crates/librqbit/src/tests/mod.rs crates/librqbit/src/tests/test_util.rs crates/librqbit/src/tests/tunnel.rs
git commit -m "test: cover tunnel client and server roles"
```

### Task 3: Verify carrier and encrypted-wire traffic contracts

**Files:**
- Create: `crates/librqbit/src/tunnel/test_capture.rs`
- Modify: `crates/librqbit/src/tests/tunnel.rs`
- Test: inline tests in `test_capture.rs`

**Interfaces:**
- Consumes: test-only wrapped client-to-server I/O and normalized `Message` events.
- Produces: `RawCapture`, `CarrierTrace`, and assertion helpers.

- [ ] **Step 1: Write failing capture contract tests**

Test that a raw capture after peer-wire negotiation contains neither a SOCKS hostname nor port literal nor application payload, that decrypting it via the test peer yields the expected frame, and that the normalized trace includes extended handshake plus bitfield, interest, request, and piece events during an active tunnel.

```rust
#[tokio::test]
async fn active_tunnel_has_encrypted_payload_and_valid_carrier_events() {
    let fixture = TunnelFixture::start_with_capture().await;
    fixture.send_socks_payload(b"secret-for-capture").await;
    let capture = fixture.raw_client_to_server_capture();
    assert!(!capture.contains(b"secret-for-capture"));
    assert!(!capture.contains(b"echo.tunnel.test"));
    fixture.carrier_trace().assert_contains_in_order(&[
        CarrierEvent::ExtendedHandshake,
        CarrierEvent::Bitfield,
        CarrierEvent::Interested,
        CarrierEvent::Request,
        CarrierEvent::Piece,
    ]);
}
```

- [ ] **Step 2: Run the capture tests and confirm they fail**

Run:

```bash
cargo test -p librqbit tunnel_capture -- --nocapture
```

Expected: compilation failure because test capture helpers are absent.

- [ ] **Step 3: Implement test-only raw capture and trace normalization**

Wrap the client-to-server stream before decryption in tests only. Store chunks in a bounded in-memory `RawCapture`; assert a configured maximum capture size. Derive `CarrierTrace` from parsed messages, recording only protocol event kind and payload lengths, never decrypted tunnel content. The trace assertion must require actual carrier piece events, not merely a custom extension handshake.

- [ ] **Step 4: Run capture and ordinary-torrent regression tests**

Run:

```bash
cargo test -p librqbit tunnel_capture -- --nocapture
cargo test -p librqbit e2e -- --nocapture
cargo test -p librqbit --lib -- --nocapture
```

Expected: encrypted-payload, carrier-trace, and existing library tests pass.

- [ ] **Step 5: Commit capture-based verification**

```bash
git add crates/librqbit/src/tunnel/test_capture.rs crates/librqbit/src/tests/tunnel.rs
git commit -m "test: verify encrypted tunnel carrier traffic"
```

### Task 4: Update operational documentation and run final checks

**Files:**
- Modify: `crates/rqbit/README.md`
- Modify: `crates/librqbit/README.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: final public CLI flags and `TunnelOptions` API.
- Produces: separate client/server deployment examples, visibility boundary, and security defaults.

- [ ] **Step 1: Write documentation acceptance examples**

Document one VPS server invocation and one desktop client invocation with file paths for keys/pairing. State that local applications point at the client loopback SOCKS address; state that client-to-VPS is the encrypted carrier leg and VPS-to-destination is normal destination traffic. State that no DHT/tracker is used for the tunnel and server allowlists client keys.

- [ ] **Step 2: Verify examples against CLI help**

Run:

```bash
cargo run -p rqbit -- server start --help
```

Expected: every documented tunnel flag appears with the same name and role restriction.

- [ ] **Step 3: Run final project checks**

Run:

```bash
cargo test -p librqbit-peer-protocol -- --nocapture
cargo test -p librqbit --lib -- --nocapture
cargo test -p rqbit tunnel_ -- --nocapture
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Expected: all focused and project checks pass without formatter or Clippy findings.

- [ ] **Step 4: Commit documentation and final verification state**

```bash
git add README.md crates/rqbit/README.md crates/librqbit/README.md
git commit -m "docs: document rqbit tunnel roles"
```
