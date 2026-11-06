# SwifHS v0 known-answer notes

Executable vectors live as unit tests in `crates/swif-session/src/handshake.rs`:

- `handshake_agrees` — full HS key agreement
- `ticket_resume_under_2s` — `resume_fast`
- `ticket_resume_fs_agrees` — `resume_fs`
- `wrong_server_key_fails` — cover-path precondition (client reject)
- `wrong_ticket_proof_fails` — bad resume PSK

Labels (UTF-8, no NUL):

| Label | Use |
|-------|-----|
| `client-es` | full HS client proof over `es` |
| `server-ee` | full HS server proof over `ee` |
| `ticket-secret` | resume PSK from `shared` |
| `client-resume` / `server-resume` | fast resume |
| `client-resume-fs` / `server-resume-fs` | FS resume |

Deterministic KATs with fixed RNG seeds can be added once a `test-vectors` feature pins `EphemeralKeypair` generation; until then agreement tests are the CI gate.
