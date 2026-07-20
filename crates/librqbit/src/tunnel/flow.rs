// ── Per-stream flow control + idle supervision ──────────────────────────────
//
// Two small primitives shared by the server relay and the client mux:
//
//   * `SendCredit` — credit-based flow control. A sender must `reserve(n)`
//     before transmitting `n` payload bytes; the peer replenishes credit via
//     `Credit` frames as it drains received data. This bounds the amount of
//     unacknowledged in-flight data per stream to the configured window
//     (`DEFAULT_WINDOW` by default), which in turn bounds the receiver's
//     per-stream buffer — so a single slow stream can never fill a buffer
//     deep enough to block the shared frame reader (no head-of-line blocking
//     across streams).
//
//   * `IdleGuard` — a bidirectional idle watchdog. Activity in EITHER
//     direction pokes it; if nothing happens for the idle timeout the stream
//     token is cancelled. (The previous implementation only timed the
//     destination-read direction, so a busy upload with a quiet download
//     direction was wrongly reset.)

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use super::config::DEFAULT_WINDOW;

// ── Credit-based flow control ───────────────────────────────────────────────

/// Send-side flow-control credit for one stream direction.
#[derive(Clone)]
pub(crate) struct SendCredit {
    sem: Arc<Semaphore>,
}

impl SendCredit {
    /// A fresh credit pool seeded with the default window.
    pub(crate) fn new() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }

    /// A fresh credit pool seeded with `window` bytes of credit. This is the
    /// seam a later task uses to pass a per-stream adaptive value; `new()`
    /// just fixes it to `DEFAULT_WINDOW`.
    pub(crate) fn with_window(window: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(window)),
        }
    }

    /// Wait until `n` bytes of credit are available and consume them.
    ///
    /// Returns `false` if the pool was [`close`](Self::close)d (stream torn
    /// down) — callers should stop sending. `acquire_many` is cancel-safe, so
    /// this may be raced in a `select!`.
    pub(crate) async fn reserve(&self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        // Chunks are always <= the configured window, so this fits the pool.
        match self.sem.acquire_many(n as u32).await {
            Ok(permit) => {
                permit.forget();
                true
            }
            Err(_) => false,
        }
    }

    /// Replenish `n` bytes of credit (the peer drained `n` bytes downstream).
    pub(crate) fn grant(&self, n: usize) {
        if n == 0 {
            return;
        }
        // Cap defensively so we never exceed the semaphore's permit ceiling.
        let n = n.min(Semaphore::MAX_PERMITS);
        self.sem.add_permits(n);
    }

    /// Permanently close the pool, waking any pending `reserve` with `false`.
    pub(crate) fn close(&self) {
        self.sem.close();
    }
}

impl Default for SendCredit {
    fn default() -> Self {
        Self::new()
    }
}

// ── Bidirectional idle watchdog ─────────────────────────────────────────────

/// Cancels `token` if no activity is reported for `idle`. Any direction of a
/// stream reports activity via [`poke`](Self::poke).
#[derive(Clone)]
pub(crate) struct IdleGuard {
    notify: Arc<Notify>,
}

impl IdleGuard {
    /// Spawn the watchdog task. It stops when `token` is cancelled (by us on
    /// timeout, or by the owner on normal teardown).
    pub(crate) fn spawn(idle: Duration, token: CancellationToken) -> Self {
        let notify = Arc::new(Notify::new());
        let watch = notify.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(idle) => {
                        token.cancel();
                        break;
                    }
                    // Activity: loop, which re-arms the sleep from now.
                    _ = watch.notified() => {}
                }
            }
        });
        Self { notify }
    }

    /// Report activity, resetting the idle countdown.
    pub(crate) fn poke(&self) {
        self.notify.notify_one();
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_window_allows_exactly_window_bytes_then_blocks() {
        let credit = SendCredit::with_window(1024);

        // Reserving the whole window (and a zero-sized reserve) succeeds
        // immediately.
        assert!(credit.reserve(0).await);
        assert!(credit.reserve(1024).await);

        // The pool is now exhausted: a further reserve must stay pending
        // until credit is granted back.
        let pending = credit.reserve(1);
        tokio::pin!(pending);
        let timed_out = tokio::time::timeout(Duration::from_millis(50), &mut pending).await;
        assert!(
            timed_out.is_err(),
            "reserve(1) should still be pending once the window is exhausted"
        );

        // Granting credit unblocks it.
        credit.grant(1);
        assert!(pending.await);
    }
}
