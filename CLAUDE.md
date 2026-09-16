# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## What this is

**Anton** (package name `anton`) is a defensive anti-ransomware detection/demo tool:
real-time file-system watcher + behavioral/entropy/extension/canary detection engine,
a Slint desktop GUI, a React web dashboard, a REST API server, and a **sandboxed**
ransomware simulator (`demo_ransomware`) used to demo the detector. The simulator only
renames files to `.cordyceps` and prepends a 4-byte magic header inside a directory it
controls (`TestRun`, `strip_prefix`-checked) — it never encrypts real content or
recurses outside its root. Treat this as legitimate security-demo tooling, not malware.

This folder was renamed from "Code Craft" to "Anton" to match the package name.

## Build & run

```bash
cargo build --release          # all 4 binaries -> target/release/
cargo test --release           # unit tests
./target/release/anton          # CLI + GUI (GUI when run with no args)
./target/release/anton_api      # REST API on :8080
./target/release/anton_desktop  # GUI only
```

macOS app bundle + DMG:
```bash
./build_and_install.sh          # builds Anton.app, adds a Desktop alias
bash macos/build_dmg.sh         # + a distributable .dmg
```

Containers (Podman/OrbStack) for the CLI/API/web — **not** the GUI (a Linux container
can't produce a working Cocoa-linked macOS binary):
```bash
docker build -t anton-rust -f containers/Containerfile.rust .
docker build -t anton-web -f containers/Containerfile.web .
```

Web frontend: `cd web && npm install && npm run dev` (`:5173`, talks to `anton_api` on `:8080`).

Full details, prerequisites, and the CLI command reference: see README.md's
"Build & Run on macOS" section and "CLI Commands".

## History: this was ported from Windows on 2026-09-16

Nothing in this crate built on **any** platform before that port — `ui/appwindow.slint`
(the entire Slint UI) and the whole `web/` React dashboard were missing (never
checked in, not just lost in the Windows→Mac transfer). Both were recreated/built from
scratch based on what the Rust/API code already expected. If you're touching
`src/desktop.rs`, `src/main.rs`, or `ui/*.slint`, know that the UI file has no
"original" to diff against — it was authored by reverse-engineering the exact
`ui.set_*`/`ui.on_*` calls already in the Rust source.

Real bugs found and fixed by actually running the built app (not just static review) —
worth knowing about since they're easy to reintroduce:
- **Infinite remediation feedback loop**: `reset_test_run_files` (called by
  auto-remediation) deletes the honeytoken canaries and creates a burst of new demo
  files — which the watcher itself detects as ransomware-like behavior, re-triggering
  remediation forever. Fixed in `watcher.rs` with a `remediating: AtomicBool` guard +
  a 2-second quiet period after remediation (tuned for macOS FSEvents' higher latency
  vs. Windows' ReadDirectoryChangesW — don't shrink this without re-testing an actual
  `anton demo` run). Canaries are now redeployed at the end of `reset_test_run_files`
  (previously permanently gone after the first remediation each session).
- **Hardcoded `.exe` suffixes** in `main.rs::run_demo()` and the GUI's `on_run_demo`
  relaunch broke sibling-binary lookup on macOS — use `std::env::consts::EXE_SUFFIX`.
- `api_server.rs` is its own crate root (redeclares `mod ...;` rather than depending on
  the `anton` lib) and was missing `mod demo_log;` even though `watcher.rs` calls
  `crate::demo_log::*` — unrelated to the port, just never caught before nothing built.
- `main.rs`/`desktop.rs` had ~300 lines of drifted duplicate GUI code; `desktop.rs` is
  now the single canonical `run_desktop()`, called by both `main.rs` and `slint_main.rs`.

Robustness/perf hardening also done in this pass (see git log for the full list):
`panic = "unwind"` + `CatchPanicLayer` + poison-recovering mutex locks in `api_server.rs`;
throttled the per-file-event OS process-table scan in `behavior_engine.rs`; bounded
file reads instead of loading whole files for entropy checks; `opt-level = 3` (was
`"z"`, which optimizes for size, not the stated "fast" goal); `simulators.rs`/`crypto.rs`
unwraps replaced with real error handling (`thiserror`); `tracing` structured logging.

**Cleanup pass (same day):** `api_server.rs` no longer redeclares `mod X;` for every
module — it depends on the `anton` lib crate via `use anton::...` like every other
binary, which dropped its warning count from 32 to ~0 (it was duplicate-compiling every
module in a narrower context where most functions looked unused; this was also the
root cause of the missing-`mod demo_log;` bug above). `cargo build`/`cargo clippy` are
both completely clean now (zero warnings workspace-wide). Removed genuinely dead code
found this way (`AppState.recovery`, `RecoveryEngine.enable_raptorq`). Untracked
`TestRun/`/`demo_log.txt` from git — pure runtime output the app regenerates from
scratch every run, not fixture data.

See README.md's "Known Limitations" for the Vault stub, GUI-can't-be-auto-verified
caveat, ad-hoc signing/Gatekeeper note, `TestRun` path constraint, the demo-stub API
endpoints, and a moderate dev-only npm vulnerability that's not worth a breaking fix.

## Architecture

| Binary | Source | Role |
|---|---|---|
| `anton` | `src/main.rs` | CLI (`run`/`demo`/`simulate`/`reset`/`revert`) + GUI (no args) |
| `anton_desktop` | `src/slint_main.rs` | GUI only, delegates to `anton::desktop::run_desktop()` |
| `anton_api` | `src/api_server.rs` | Axum/Tokio REST server, its own crate root |
| `demo_ransomware` | `src/demo_ransomware.rs` | The sandboxed simulator, spawned as a child process by `anton demo` |

Key library modules: `watcher.rs` (notify-based FS watcher + auto-remediation),
`ai.rs`/`detectors.rs`/`behavior_engine.rs` (detection signals → `DetectionResult`),
`canary.rs` (honeytoken files), `simulators.rs`/`simulation.rs` (test/demo ransomware
behaviors, self-test sandbox), `crypto.rs` (entropy, AEAD, HMAC — generic utilities, not
part of the simulator), `recovery.rs` (shadow-copy restore), `desktop.rs` (the one
canonical Slint GUI implementation), `demo_log.rs` (plain-text demo transcript, not
diagnostic logging — leave it as `println!`/file-write, don't "fix" it into `tracing`).

`Config::for_test_run()` resolves `TestRun`/`ShadowCopies` relative to
`CARGO_MANIFEST_DIR` (build-time location), not a per-user data directory — existing
design constraint, not introduced by the port.

`Vault` (web dashboard and, implicitly, the GUI) is an explicit stub — "coming soon" per
the README, no `/api/vault/*` routes exist. Don't build real functionality for it
without being asked; it's intentionally unimplemented.

## graphify

This project has a graphify knowledge graph at graphify-out/. Note: the graphify CLI is
not installed on this machine as of the port above, so `graphify update .` could not be
run after that session's changes — the graph may be stale relative to current code.

Rules:
- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)
