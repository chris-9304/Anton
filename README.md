# Anton - Professional Anti-Ransomware System

A professional-grade anti-ransomware software built with Rust backend and React frontend.

## Features

### Backend (Rust)
- **Real-time File System Monitoring**: Low-level file system event watching
- **Behavioral Analysis**: Frequency, extension, behavior, and entropy analysis
- **AI Classification Engine**: Rule-based threat detection with confidence scoring
- **Cryptographic Protection**:
  - AES-256-GCM encryption
  - ChaCha20-Poly1305 encryption
  - RSA key generation
  - RaptorQ FEC for file redundancy
- **File Recovery**: Shadow copies and automatic restoration
- **REST API**: HTTP server with CORS support

### Desktop GUI (Slint)
- Native desktop app (`anton` with no arguments, or `anton_desktop`) with the same
  Dashboard / Scan / Settings surface as the web frontend, plus one-click "Run
  Ransomware Demo" / "Revert Demo" buttons for live demonstrations.

### Frontend (React + Vite + Tailwind)
- **Dashboard**: Real-time system overview with stats and charts
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
cargo run --bin anton_api
```

The API server will run on `http://localhost:8080`

### Frontend Setup

1. Install dependencies:
```bash
cd web
npm install
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

Unchanged from the Quick Start section above — `cd web && npm install && npm run dev`
(serves on `http://localhost:5173` and talks directly to `anton_api` on `:8080`; CORS is
already permissive server-side, no proxy needed).

### Containers (Podman / OrbStack)

The CLI, `anton_api`, `demo_ransomware`, and the web frontend all build and run fine in
a Linux container. The desktop GUI does not: `anton_desktop` (and `anton`'s GUI mode)
links against Cocoa/AppKit, which has no equivalent inside a Linux container — build and
package that natively instead (see below).

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
- `POST /api/scan/quick`: Trigger quick scan
- `POST /api/scan/full`: Trigger full scan

## Testing

The system includes safe ransomware simulators for testing:
- Old-style ransomware: Slow rename with classic extensions
- Modern ransomware: Fast parallel encryption
- Wiper malware: Mass file deletion

All simulators operate only in the `TestRun` directory and include automatic cleanup.

## Security Features

- Real-time file system monitoring
- Behavioral pattern detection
- Cryptographic file protection
- Automatic threat response
- File recovery capabilities
- Low resource usage

## Known Limitations

- **Vault** (both the desktop GUI and the web dashboard) is a stub — "coming soon," no
  `/api/vault/*` routes exist yet.
- The desktop GUI's rendering can't be verified by an automated agent — if you're
  scripting a build/test pipeline, treat a clean launch (no panic/crash) as the
  automatable check, and visually confirm the window and its tabs/buttons by hand.
- The macOS `.app` is ad-hoc signed, not notarized — Gatekeeper will block first launch
  until you right-click → Open (or clear the quarantine attribute).
- `Config::for_test_run()` resolves `TestRun`/`ShadowCopies` relative to
  `CARGO_MANIFEST_DIR`, i.e. wherever the binary was *built*, not a per-user data
  directory — this is an existing design constraint (not introduced by the macOS port),
  worth knowing before relying on it for anything beyond local development/demos.
- `npm audit` flags a moderate-severity `esbuild`/Vite dev-server vulnerability
  ([GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99)) in
  `web/`. It only affects `npm run dev` (a malicious website could probe the local dev
  server) — production builds (`npm run build`, what actually ships) are unaffected.
  The fix requires a breaking Vite 8 upgrade that `@vitejs/plugin-react` doesn't
  officially support yet (its peer range tops out at `^7.0.0`); attempting it produced
  new build warnings and a broken JSX option, so it was reverted. Revisit once
  `@vitejs/plugin-react` adds Vite 8 support.
- The API server's `/api/scan/quick` and `/api/scan/full` endpoints are demo stubs —
  they record a `ScanRecord` and return a canned "no threats found" response rather
  than triggering a real scan. `/api/status`'s `threats_blocked`/`files_monitored`/
  `heuristic_score` are likewise fixed demo values, not live counters. Pre-existing,
  not introduced by this pass.

## License

Professional anti-ransomware system - All rights reserved
