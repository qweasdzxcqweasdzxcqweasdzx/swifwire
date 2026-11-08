//! Ticket replay window (server-side bloom-ish set).

use std::collections::HashSet;

use sha2::{Digest, Sha256};

/// Bounded set of recently seen ticket digests (anti-replay for resume).
#[derive(Debug, Default)]
pub struct TicketReplayWindow {
    seen: HashSet<[u8; 16]>,
    capacity: usize,
}

impl TicketReplayWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            capacity: capacity.max(64),
        }
    }

    fn digest(ticket: &[u8]) -> [u8; 16] {
        let h = Sha256::digest(ticket);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h[..16]);
        out
    }

    /// Returns true if this ticket was **already** seen (replay). Inserts on first sight.
    pub fn check_and_insert(&mut self, ticket: &[u8]) -> bool {
        if ticket.is_empty() {
            return false;
        }
        let d = Self::digest(ticket);
        if self.seen.contains(&d) {
            return true;
        }
        if self.seen.len() >= self.capacity {
            // drop arbitrary element (HashSet iter order)
            if let Some(old) = self.seen.iter().next().copied() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(d);
        false
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_replay() {
        let mut w = TicketReplayWindow::new(128);
        assert!(!w.check_and_insert(b"ticket-a"));
        assert!(w.check_and_insert(b"ticket-a"));
        assert!(!w.check_and_insert(b"ticket-b"));
    }
}
