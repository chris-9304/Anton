# Anton

A Rust and React sandbox for demonstrating ransomware-pattern detection and recovery.
It includes a native desktop app, web dashboard, API, and CLI.

## Features

### Backend (Rust)
- **Real-time File System Monitoring**: Low-level file system event watching
- **Behavioral Analysis**: Frequency, extension, behavior, and entropy analysis
- **AI Classification Engine**: Rule-based threat detection with confidence scoring
- **Cryptographic Protection**:
  - AES-256-GCM encryption
  - ChaCha20-Poly1305 encryption
  - RSA key generation
  - Legacy XOR parity helpers (not a complete RaptorQ implementation)
- **File Recovery**: Shadow copies and automatic restoration
- **REST API**: HTTP server with CORS support

### Desktop GUI (Slint)
- Native desktop app (`anton` with no arguments, or `anton_desktop`) with the same
  Dashboard / Scan / Settings surface as the web frontend, plus one-click "Run
  Ransomware Demo" / "Revert Demo" buttons for live demonstrations.

### Frontend (React + Vite + Tailwind)
- **Dashboard**: Real-time system overview with status and recent detections
- **Scan Activity**: View scan history and results
- **History**: Backend activity logs
- **Settings**: Configure AI detection and monitoring
- **Vault**: Protected files management (coming soon)

## Quick Start

### Prerequisites
- Rust (latest stable)
- Node.js 18+ and npm
- Cargo

### Backend Setup

1. Build and run the API server:
```bash
cargo run --no-default-features --bin anton_api
```

The API server defaults to `http://localhost:8080`. Set `ANTON_API_ADDR` to change
the bind address, for example `127.0.0.1:18089`. Set `VITE_API_BASE_URL` before
starting or building the frontend when using a different API address.

### Frontend Setup

1. Install dependencies:
```bash
cd web
npm ci
```

2. Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:5173`

### CLI Commands

```bash
# Launch the desktop GUI (default, no arguments)
cargo run --bin anton

# Start monitoring (CLI, no GUI)
cargo run --bin anton -- run

# Run the sandboxed ransomware demo, then automatically detect + restore
cargo run --bin anton -- demo

# Run ransomware simulators (for testing)
cargo run --bin anton -- simulate old      # Old-style ransomware
cargo run --bin anton -- simulate modern  # Modern ransomware
cargo run --bin anton -- simulate wiper   # Wiper malware

# Reset test files
cargo run --bin anton -- reset

# Restore TestRun from backup / remove locked files
cargo run --bin anton -- revert
```

## Build & Run on macOS

Anton was originally developed on Windows. It now also builds and runs natively on
macOS (verified on Apple Silicon).

### Prerequisites

- Rust (via [rustup](https://rustup.rs))
- Node.js 18+ and npm
- Xcode Command Line Tools (`xcode-select --install`) — needed to link the desktop
  GUI's Cocoa/AppKit backend
- Optional: [Podman](https://podman.io) or [OrbStack](https://orbstack.dev) if you want
  to build/run the backend and web frontend in containers (see below)

### Native build

```bash
cargo build --release
```

This produces all four binaries in `target/release/`:

| Binary | What it is |
|---|---|
| `anton` | CLI + desktop GUI (GUI when run with no arguments; see CLI Commands above) |
| `anton_desktop` | Desktop GUI only, same UI as `anton`'s GUI mode |
| `anton_api` | REST API server (`http://localhost:8080`) |
| `demo_ransomware` | The sandboxed ransomware simulator, normally launched automatically by `anton demo` |

Run any of them directly, e.g. `./target/release/anton_api`, `./target/release/anton demo`.

### Web frontend

Unchanged from the Quick Start section above — `cd web && npm ci && npm run dev`
(serves on `http://localhost:5173` and talks directly to `anton_api` on `:8080`; CORS is
already permissive server-side, no proxy needed).

### Containers (Podman / OrbStack)

The Rust container builds with `--no-default-features`: CLI/API binaries exclude Slint,
GUI compilation, and GUI system libraries. Desktop applications must be built for the
host desktop platform. The web container uses `npm ci`; its API URL is configurable
with `--build-arg VITE_API_BASE_URL=http://your-api:8080`.

```bash
# Backend (anton, anton_api, demo_ransomware)
docker build -t anton-rust -f containers/Containerfile.rust .
docker run --rm -p 8080:8080 anton-rust api          # anton_api
docker run --rm anton-rust cli reset                 # any `anton <subcommand>`
docker run --rm anton-rust demo /path/in/container    # demo_ransomware

# Web frontend (served via nginx)
docker build -t anton-web -f containers/Containerfile.web .
docker run --rm -p 4173:80 anton-web
```

(Substitute `podman` for `docker` if you have a Podman machine provisioned —
`podman machine init && podman machine start` — otherwise any OCI-compatible engine,
including OrbStack's `docker` CLI, works with the commands above unchanged.)

### macOS App Bundle & DMG

```bash
./build_and_install.sh        # builds Anton.app and adds a Desktop alias
# or, individually:
bash macos/build_app_bundle.sh   # just the .app
bash macos/build_dmg.sh          # .app + a distributable Anton-<version>.dmg
```

The app is ad-hoc code-signed (no Apple Developer ID), so on first launch macOS
Gatekeeper will block it — right-click `Anton.app` and choose **Open**, or run
`xattr -d com.apple.quarantine Anton.app`.

## Architecture

### Backend Modules
- `config.rs`: Configuration management
- `models.rs`: Data models (events, threats, detections)
- `detectors.rs`: Detection analyzers (frequency, extension, behavior, entropy)
- `behavior_engine.rs`: Owlyshield-style process-family behavioral analysis
- `canary.rs`: Honeytoken/canary bait files
- `ai.rs`: AI classification engine
- `watcher.rs`: File system watcher
- `crypto.rs`: Cryptographic utilities
- `recovery.rs`: File recovery and backup
- `simulators.rs` / `simulation.rs`: Test ransomware simulators and the internal sandboxed self-test
- `demo_log.rs`: Plain-text demo transcript logger
- `app_settings.rs`: Shared runtime toggles (UI ⟷ watcher)
- `demo.rs`: Shared cancellable demo controller, child ownership, and restore flow
- `scanner.rs`: Streaming directory scans and bounded progress publication
- `desktop.rs`: Slint desktop GUI (`anton`'s GUI mode and `anton_desktop`)
- `api_server.rs`: HTTP API server
- `demo_ransomware.rs`: The sandboxed ransomware simulator binary itself

### Frontend Structure
- `src/App.jsx`: Main application component
- `src/services/api.js`: API client
- Components: Dashboard, Settings, History, Scan Activity, Vault (stub)

## API Endpoints

- `GET /api/status`: System status and statistics
- `GET /api/detections`: Recent detections
- `GET /api/logs`: Activity logs
- `GET /api/scans`: Scan history
- `POST /api/settings/ai`: Toggle AI engine
- `POST /api/settings/monitoring`: Toggle monitoring
- `POST /api/scan/quick`: Record a simulated quick scan
- `POST /api/scan/full`: Record a simulated full scan

## Settings and resource limits

- Monitoring off pauses analysis, canary protection, and automatic recovery. AI off
  skips heuristic analysis while keeping canary protection active. The desktop
  diagnostic pauses its main subscription and owns a watcher confined to the test
  sandbox; it subscribes after setup to avoid detecting its own initialization.
  Settings changes
  invalidate stale detector state and queued events from previous settings. Queued
  events retain their arrival timestamps so slow I/O does not distort rate windows.
- The watcher owns one worker and a 2,048-event queue. Native watcher errors or queue
  overflow mark monitoring as degraded; status includes `monitoring_health` and
  `dropped_events`. Degraded status stays set until the watcher is restarted.
- Each detector window retains at most 4,096 samples. Process-family state is bounded
  and unknown PID `0` avoids process-table collection. File inspection reads 4 KiB.
- API history retains 100 logs, 50 detections, and 1,000 scan records; cumulative
  counters continue increasing. Desktop activity retains 1,000 rows and pending
  activity is bounded. Scan progress publishes at most every 100 ms plus completion.
- Desktop scans stream files to depth 6 without following symbolic links, report
  skipped files, and show indeterminate progress until completion. High entropy is a
  heuristic and can flag legitimate compressed/encrypted files.
- Web requests time out after 10 seconds. Polling waits for completion, cancels on
  navigation, and pauses while the page is hidden. Scan history renders 50 rows at a time.
- Demo transcripts rotate to `demo_log.txt.1` at 5 MiB, retaining two files. Processes
  reopen on append; simultaneous parent/child writes may briefly exceed the rotation
  threshold by an in-flight write. Phase and remediation messages remain enabled.
- Backups are streamed and verified before removal. A pending `TestRun_backup`
  prevents another demo from replacing it. Shadow copies have integrity sidecars;
  legacy copies without sidecars are retained but cannot be automatically verified.
  Automatic encrypted-file cleanup restores only verified originals with unambiguous
  appended suffixes such as `report.txt.locked`; ambiguous replacement suffixes remain.

The `.app` contains `anton` and `demo_ransomware`; the duplicate desktop-only GUI binary
is no longer bundled. `anton_desktop` remains available as a separate build target.
Runtime directories and protected-folder settings keep their existing locations.

## Testing and measured performance

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --no-default-features --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --no-default-features --all-targets
cargo test --locked --release --no-default-features --test regressions scan_ten_thousand_files -- --ignored --nocapture
cargo run --locked --release --no-default-features --example resource_probe
cd web
npm test
npm run build
```

macOS watcher and demo integration tests require native FSEvents access. A sandbox
that suppresses FSEvents can cause their detection deadlines to expire.

For optional browser checks, install Playwright in your development environment,
start Vite on port 18765, and run `npm run test:ui`. `ANTON_WEB_URL` changes the test
URL; `PLAYWRIGHT_PATH` can point to an existing Playwright installation, and
`ANTON_BROWSER_EXECUTABLE` can select an installed Chromium browser. Browser checks
cover mobile layout, severity styling, scan fields, failed settings, keyboard use,
and offline feedback. The native desktop still needs a visual review on each target OS.

Measured on this Apple Silicon development machine, release builds, three runs of
20,000 synthetic create events with the same timestamp and 100 directory names:

| Detector workload | Before (`e39358a`) | After |
|---|---:|---:|
| Median total time | 621 ms | 306 ms |
| Median peak process RSS | 12.31 MiB | 6.36 MiB |

The comparison compiled the original detector modules and current modules with the
same locked dependencies and workload in `examples/resource_probe.rs`. This is a
synthetic detector benchmark, not a measurement of whole-application RAM or end-to-end
filesystem latency. The bounded windows intentionally retain only the latest samples
under sustained bursts. A separate 10,000-file release scan completed in 184 ms with
2 progress publications on a warm local filesystem; results vary with storage and load.

Build artifacts can be regenerated with `cargo build --locked --release`. `cargo clean`
reclaims local Rust build caches; it does not remove runtime files or download caches.
Development debug information is reduced to level 1 and release debug information
is stripped. No dependency major-version upgrades are included in this cleanup.
After verification and a clean release rebuild, local Rust artifacts occupy about
2.0 GiB, compared with the original 7.5 GiB. Runtime files and backups were retained.

## Known limitations

- Vault remains an explicit placeholder with no backend routes.
- API quick/full scans are simulations and do not inspect files. Status exposes
  `demo_mode: true`; file count and heuristic score remain sample values. Detection
  and scan counters are live session counters.
- Saved folders are preferences only; monitoring still watches TestRun. No network
  event source feeds the DNS analyzer; its desktop control is disabled.
- `Config::for_test_run()` retains `CARGO_MANIFEST_DIR`-relative TestRun/ShadowCopies.
  Installed applications therefore still depend on their build-time checkout path.
- The app bundle is ad-hoc signed, not notarized. Platform permissions and Gatekeeper
  may require a manual first launch.
- Compatible dependency updates fixed the PostCSS selector-parser and source-map-js
  advisories. The 2026-11-20 npm audit still reports two build-tool vulnerabilities
  (one moderate, one high) through Vite/esbuild. Their suggested fix requires a major
  Vite upgrade; that migration is outside this cleanup.
- The legacy `RaptorQEncoder` API is a simple XOR parity demonstration. It does not
  implement general RaptorQ erasure recovery. Overwriting a file before deletion also
  cannot guarantee physical erasure on SSD or copy-on-write filesystems.

## License

All rights reserved
