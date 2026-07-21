# Plan B — Active-Probe Resistance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the tunnel server indistinguishable from a real BitTorrent seeder to an active, unauthenticated prober — it serves valid pieces of the fake torrent to anyone who speaks BT, and NEVER exhibits the "completes obfuscated/BT handshake then drops" tell. It promotes a connection to tunnel-relay mode ONLY when a valid, allowlisted Noise handshake arrives inside an `rq_tunnel` message; every other peer is simply seeded, then idle-disconnected like a normal BT peer.

**Architecture:** Replace the server's post-`establish` phase — currently `recv_one_ciphertext` (waits for one `rq_tunnel` ciphertext, IGNORING cover `Request`s) → `responder_accept` → drop on failure — with a **seeder session loop** that: serves `Request`→`Piece` cover, honors choke/unchoke with bounded upload slots, watches for an `rq_tunnel` ciphertext and tries Noise promotion on it, and on ANY failure (bad Noise, non-allowlisted key, non-rq_tunnel traffic) just keeps seeding until an idle timeout. This removes both current tells. Client side is unchanged (it dials out; nothing probes it).

**Tech Stack:** Rust, tokio, `peer_binary_protocol`, existing `carrier_peer`/`carrier_wire`/`crypto`.

## Global Constraints
- BEP 52 v2 only. Prefer typed errors over `anyhow` on verification paths.
- MSE key stays `derive_carrier_hash`; DHT/handshake use `handshake_info_hash` (unchanged from Plan A).
- No new pre-auth panic / unbounded allocation (the seeder loop runs pre-Noise, reachable by anyone who knows `server_pub`).
- After each task: `cargo check -p librqbit` + `cargo clippy -p librqbit --all-targets` clean; `cargo fmt --all` before commit; full `cargo test -p librqbit tunnel` stays green.
- Use repo-local `TMPDIR` for cargo (the session `/tmp` has a per-user quota).

## File Structure
- Modify: `carrier_peer.rs` — add server-side seeder helpers (serve request when unchoked; upload-slot/choke state).
- Modify: `server.rs` — `accept` returns an outcome enum; new `seed_until_promoted` loop; accept loop enforces connection caps.
- Modify: `carrier_chunk.rs` — `recv_one_ciphertext` stays for the CLIENT; server stops using it.
- Test: `crates/librqbit/src/tests/tunnel.rs` — active-probe E2E test (stub BT client).

---

## Task 1: Seeder session loop — serve cover + promote on valid Noise, never tell

Replace the server's `recv_one_ciphertext`→`responder_accept`→drop with a loop that seeds and promotes.

**Files:**
- Modify: `crates/librqbit/src/tunnel/server.rs` (`accept` body after `into_halves`)
- Modify: `crates/librqbit/src/tunnel/carrier_peer.rs` (a `serve_request` path usable outside `on_message`, if needed)
- Test: `server.rs` unit test for the promotion/no-drop outcomes

**Interfaces:**
- Produces on `server.rs`:
  - `enum AcceptOutcome { Admitted(AdmittedPeer), Seeded }` — `Seeded` = the peer was a prober/real-BT-peer that never authenticated and hit idle/disconnect; the caller just closes the socket (a normal BT churn event), no error.
  - `async fn seed_until_promoted(read_half, write_half, carrier_peer, transport-inputs, idle: Duration) -> AcceptOutcome`

- [ ] **Step 1: Write the failing test**

Add to `server.rs` `mod tests` a test that drives (in-process, over `tokio::io::duplex`) a peer that: completes MSE + `CarrierWire::establish`, then sends a `Request` and expects a `Piece` back (served during the wait), then sends an INVALID `rq_tunnel` payload and asserts the server does NOT close the connection (keeps seeding) — i.e. a subsequent `Request` still gets a `Piece`. (If a full duplex harness is heavy, assert at the `seed_until_promoted` level with a scripted `CarrierReadHalf` fake.) Then a second test: a VALID allowlisted Noise init in `rq_tunnel` yields `AcceptOutcome::Admitted`.

Run: `cargo test -p librqbit tunnel::server 2>&1 | tail -20` — expect FAIL (function missing).

- [ ] **Step 2: Implement `seed_until_promoted`**

Replace the current `accept` steps 3–5 (`server.rs` recv_one_ciphertext → responder_accept → build AdmittedPeer) with a call to a new `seed_until_promoted`. Sketch (adapt to real signatures):

```rust
// server.rs — new outcome + loop
pub(crate) enum AcceptOutcome {
    Admitted(AdmittedPeer),
    Seeded, // never authenticated; treat as a normal BT peer that came and went
}

async fn seed_until_promoted(
    read_half: &mut super::carrier_wire::CarrierReadHalf,
    write_half: &mut super::carrier_wire::CarrierWriteHalf,
    carrier_peer: &mut super::carrier_peer::TunnelCarrierPeer,
    identity_key: &crate::tunnel::frame::TunnelPrivateKey,
    allowed: &std::collections::HashSet<crate::tunnel::frame::TunnelPublicKey>,
    idle: std::time::Duration,
) -> Result<Option<(NoiseTransport, TunnelPublicKey)>, TunnelAdmissionError> {
    use peer_binary_protocol::{Message, extended::ExtendedMessage};
    let mut defrag = super::carrier_chunk::CarrierDefragmenter::new(
        super::carrier_chunk::MAX_CARRIER_CIPHERTEXT,
    );
    loop {
        let msg = match tokio::time::timeout(idle, read_half.recv_message()).await {
            Err(_elapsed) => return Ok(None),          // idle disconnect: normal BT churn
            Ok(Ok(Some(m))) => m,
            Ok(_) => return Ok(None),                  // peer closed / read error
        };
        match msg {
            Message::Extended(ExtendedMessage::RqTunnel(rq)) => {
                let blobs = match defrag.push(rq.as_bytes()) {
                    Ok(b) => b,
                    Err(_) => return Ok(None),         // oversized: drop like a misbehaving peer
                };
                for ciphertext in blobs {
                    if ciphertext.len() > 512 { continue; } // not a Noise init; ignore, keep seeding
                    match crypto::responder_accept(identity_key, &ciphertext, allowed) {
                        Ok((transport, key, reply)) => {
                            for chunk in super::carrier_chunk::chunk_ciphertext(&reply) {
                                write_half.send_tunnel(&chunk).await.map_err(|e| {
                                    TunnelAdmissionError::CarrierHandshakeFailed(anyhow::anyhow!("{e}"))
                                })?;
                            }
                            return Ok(Some((transport, key)));   // PROMOTE
                        }
                        Err(_) => { /* bad Noise / not allowlisted: keep seeding, no tell */ }
                    }
                }
            }
            other => {
                // Serve cover exactly like the establish early-cover path.
                match carrier_peer.on_message(other).await {
                    Ok(actions) => {
                        for a in actions {
                            if let super::carrier_peer::CarrierAction::OutgoingMessage(m) = a {
                                // best-effort; a serialize failure just skips one cover message
                                let _ = write_half.send_message(&m.to_message()).await;
                            }
                        }
                    }
                    Err(_) => { /* invalid cover request: ignore, keep seeding */ }
                }
            }
        }
    }
}
```

Then in `accept`, after `into_halves`:
```rust
    let idle = std::time::Duration::from_secs(120); // realistic BT keepalive-idle bound
    match seed_until_promoted(&mut read_half, &mut write_half, &mut carrier_peer,
                              &self.options.identity_key, &self.options.allowed_client_keys, idle).await? {
        Some((transport, client_key)) => {
            self.peers.write().await.insert(client_key.clone(), true);
            Ok(AcceptOutcome::Admitted(AdmittedPeer { client_key, transport, read_half, write_half, carrier_peer }))
        }
        None => Ok(AcceptOutcome::Seeded),
    }
```
Update `accept`'s return type to `Result<AcceptOutcome, TunnelAdmissionError>` and the accept-loop caller in `run` to match on `Admitted` (spawn relay) vs `Seeded` (just drop the socket, debug-log — no error, no tell).

NOTE the two removed tells: (a) `Request`s are now served during the wait; (b) a bad Noise / non-allowlisted key no longer drops — it keeps seeding.

- [ ] **Step 3: Run tests** — `cargo test -p librqbit tunnel 2>&1 | tail -20`. The existing admission tests may need updating to the new `AcceptOutcome` (a valid client still yields `Admitted`; the wrong-key test now yields `Seeded`, not an error — update `server_rejects_unknown_client_key_during_noise_handshake` to assert the connection is seeded/kept, not dropped).

- [ ] **Step 4: Commit** — `fix(tunnel): server seeds unauthenticated peers, promotes only on valid Noise (no drop tell)`

---

## Task 2: Bound the seeder — upload slots, choke, connection caps

A real seeder chokes most peers and bounds resources. Add: choke-by-default with a small number of unchoke (upload) slots, a per-IP and global connection cap in the accept loop, and confirm the idle timeout.

**Files:**
- Modify: `carrier_peer.rs` (choke state: only serve `Request` when the peer is unchoked; start choked, unchoke up to N)
- Modify: `server.rs` `run` accept loop (per-IP + global in-flight connection caps)
- Modify: `config.rs` (constants: `SEEDER_UPLOAD_SLOTS`, `MAX_SEEDER_CONNS_PER_IP`, `MAX_SEEDER_CONNS_TOTAL`, `SEEDER_IDLE`)
- Test: unit tests for choke gating + a cap test

- [ ] **Step 1: Write failing tests** — (a) a choked peer's `Request` yields NO `Piece` until an `Unchoke` is sent; (b) the accept loop refuses a connection beyond the per-IP cap (or, simpler to test, the cap counter logic in isolation).
- [ ] **Step 2: Implement** — add `SEEDER_*` consts to `config.rs`; in `carrier_peer`, gate `on_request` on `local_choked` (start choked; the establish `initial_messages` currently sends `Unchoke` — change to start CHOKED and unchoke only within slot budget, OR keep sending `Unchoke` but cap concurrent served peers via slots at the server level — pick the simpler correct one and document it). In `server.rs` `run`, maintain an `Arc<Mutex<HashMap<IpAddr, usize>>>` (or an `AtomicUsize` global + per-IP map) and skip/again-listen when caps are exceeded (dropping an over-cap connection is normal for a busy seeder). Keep `SEEDER_IDLE` wired into Task 1's `idle`.
- [ ] **Step 3: Run tests** — full `cargo test -p librqbit tunnel` green.
- [ ] **Step 4: Commit** — `feat(tunnel): bound seeder with upload slots + connection caps`

---

## Task 3: Active-probe E2E gate + remove dead server `recv_one_ciphertext` usage

**Files:**
- Test: `crates/librqbit/src/tests/tunnel.rs` — `active_prober_gets_seeded_and_no_disconnect_tell`
- Modify: `carrier_chunk.rs` / `server.rs` — ensure the server no longer calls `recv_one_ciphertext` (client still does); drop it from server imports.

- [ ] **Step 1: Write the failing E2E test.** A stub BT probe (built from the primitives in `carrier_wire`/`peer_binary_protocol`, mirroring what `CarrierWire::establish` does on the initiator side) that: MSE-initiates with the server's `carrier_hash`, completes the BT + BEP-10 handshake, sends `Interested` + a `Request` for piece 0 block 0 (16 KiB), receives a `Piece`, and validates its bytes against the deterministic corpus (both derive the same corpus from the server key). Then it sends a garbage `rq_tunnel` payload and asserts: the connection is STILL open and a second `Request` still returns a valid `Piece` (no obfuscation-then-disconnect tell). Assert the server never closed the socket within a bounded wait.

Run: expect FAIL until Tasks 1–2 are in and the probe helper exists.

- [ ] **Step 2: Make it pass** — reconcile with Tasks 1–2 behavior; ensure the probe (which never sends valid Noise) is seeded and not dropped, and a piece validates.
- [ ] **Step 3: Full suite green + clippy/fmt** — `cargo test -p librqbit tunnel`.
- [ ] **Step 4: Commit** — `test(tunnel): active-probe E2E gate — server seeds a probe, no disconnect tell`

---

## Self-Review checklist
- Both tells removed: (1) `Request`s served during the Noise wait (Task 1); (2) no drop on Noise/allowlist failure (Task 1). ✓
- Resource-bounded: upload slots + conn caps + idle timeout (Task 2) — pre-auth attacker can't amplify beyond a normal seeder. ✓
- Promotion still works: valid allowlisted Noise → `Admitted` → `run_server_relay` (Task 1). ✓
- No new pre-auth panic/alloc: `seed_until_promoted` reuses the bounded defragmenter; `responder_accept` failure is caught, not unwrapped. ✓
- E2E gate proves a probe downloads+validates a piece and sees no disconnect tell (Task 3). ✓
