# rqbit Tunnel Implementation Program

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an opt-in `rqbit` client/server SOCKS tunnel whose desktop-to-VPS leg uses an encrypted BitTorrent peer-wire carrier while ordinary torrents continue to work.

**Architecture:** The implementation is split into four serial, independently reviewable plans. A private BEP 52 carrier establishes legitimate torrent state; secure peer transport carries the negotiated tunnel extension; server and client roles supply egress and local SOCKS semantics; CLI and regression work expose the feature safely.

**Tech Stack:** Rust 2024, Tokio, existing `peer_binary_protocol`, BEP 52, BEP 10, MSE/PE compatibility layer, `snow` 0.9.6, `fast-socks5` 0.9.0, `sha2` 0.10.9.

## Global Constraints

- The tunnel is opt-in and never changes ordinary torrent defaults.
- Carrier metadata and verification use BEP 52 v2 structures; do not add new v1 torrent paths.
- The client-to-VPS transport has no direct-destination fallback.
- Server mode is an authenticated relay, never a public SOCKS listener.
- The client SOCKS listener defaults to loopback and preserves remote DNS resolution.
- Tunnel payload and destination metadata are encrypted end-to-end inside the peer-wire session.
- The peer-wire encryption layer is not the authentication boundary; static-key inner encryption is.
- Any traffic-similarity statement must be backed by an explicit capture-based test baseline, never phrased as a universal DPI guarantee.
- Do not store carrier state in `Session::db` or alter ordinary torrent statistics, DHT, tracker, or persistence behavior.

---

## Dependency order

1. [Carrier foundation](2026-07-19-rqbit-tunnel-carrier-foundation.md) — produces internal BEP 52 carrier metadata, persistent corpus, and a peer handler that performs valid bitfield/request/piece transitions.
2. [Secure peer transport](2026-07-19-rqbit-tunnel-secure-peer-transport.md) — produces MSE/PE-compatible stream wrapping, typed `rq_tunnel` extension messages, and authenticated encrypted tunnel frames.
3. [SOCKS roles](2026-07-19-rqbit-tunnel-socks-roles.md) — produces `TunnelOptions`, server admission/egress, client loopback SOCKS `CONNECT` and `UDP ASSOCIATE`, and no-fallback behavior.
4. [CLI and verification](2026-07-19-rqbit-tunnel-cli-verification.md) — produces role-specific CLI flags, configuration validation, end-to-end regression tests, and capture-based traffic-contract checks.

## Execution rule

Complete the plans in order. A later plan may consume only the public interfaces produced by earlier plans. At each plan boundary, run its focused tests and request review before beginning the next plan.
