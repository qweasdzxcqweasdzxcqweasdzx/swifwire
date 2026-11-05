//! Lightweight probe-gate helpers (CI): cover must look like HTTP origin.

/// Builtin cover response starts with HTTP/1.1 200 — probe gate for lab.
pub fn cover_looks_like_http_origin(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::COVER_HTML;

    #[test]
    fn probe_gate_builtin() {
        assert!(cover_looks_like_http_origin(COVER_HTML));
        assert!(!cover_looks_like_http_origin(b"SWI1"));
    }
}
