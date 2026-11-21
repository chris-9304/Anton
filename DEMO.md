# Anton Demo & Hackathon Guide

## How to Run the Anti-Ransomware (Anton)

- **Desktop (recommended):** Double-click **Anton** on the Desktop (macOS: the alias created by `build_and_install.sh`; Windows: the shortcut created by `build_and_install.bat`). Or run `anton` from the project folder after `cargo build --release`.
- **CLI monitoring:** `anton run` — starts real-time monitoring of the TestRun folder.
- **Build + shortcut:** macOS: run `./build_and_install.sh` (builds `Anton.app` and adds a Desktop alias). Windows: run `build_and_install.bat`.

## How to Run the Ransomware Demo

1. **Build both binaries:**
   `cargo build --release`
   This produces `target/release/anton` and `target/release/demo_ransomware` (macOS/Linux;
   `anton.exe` / `demo_ransomware.exe` on Windows).

2. **From GUI:**
   Open Anton, go to **Dashboard**, click **Run Ransomware Demo**. The app will back up TestRun, start the watcher, run the sandboxed demo ransomware, then stop it and restore files. Status appears in Protection Status and Threat History.

3. **From CLI:**
   `anton demo`
   Backs up TestRun, starts the watcher, runs `demo_ransomware` (sandboxed to TestRun), waits for detection or 45s, kills the ransomware, then reverts (restores files). Reports actual detection and restore results; failures return a nonzero exit status.

4. **Manual revert:**
   `anton revert` or use the **Revert Demo** button in the Dashboard to restore TestRun from backup or remove locked/encrypted files and reset sample files.

## Demo Ransomware (Sandboxed)

- **Binary:** `demo_ransomware` (`demo_ransomware.exe` on Windows) — built with `cargo build --release` or `cargo build --bin demo_ransomware`.
- **Behavior:** Only modifies files under one folder (default: project `TestRun`). For each file: renames to `.cordyceps`, writes magic header `CORD` (Cordyceps-style). No real encryption; for demonstration only.
- **Usage:** `demo_ransomware [PATH]` — default PATH is the project `TestRun` directory.
- **Safety:** Path check ensures it never leaves the given root (sandboxed to TestRun for demos).

## Fallback / No-Failure Behavior

- Even if Anton does not detect the ransomware in time, the **demo flow** still stops the ransomware process (after timeout or child exit), runs **revert**, and removes locked/encrypted files and restores from backup. So the demo attempts verified restoration and retains the backup if restoration fails.
- **Revert** restores from `TestRun_backup` if it exists; otherwise deletes files with encrypted extensions (e.g. `.cordyceps`, `.zombie`, `.locked`, `.crypt`) in TestRun and repopulates sample files.

## Key Points for Hackathon Q&A

### Anti-Ransomware (Anton)

- **Real-time monitoring:** Watches a configurable directory (e.g. TestRun) with a file system watcher; analyzes create/modify/rename events.
- **Multi-signal detection:** Uses extension blocklist (e.g. .locked, .cordyceps, .zombie), rate limiting (rapid renames/modifications), entropy (high entropy suggests encryption), and honeytoken/canary files. Combines signals into a heuristic score and threat level.
- **Canary/honeytoken:** Deploys decoy files; if they are touched (modified/deleted), triggers an immediate critical alert.
- **Recovery:** Backup of TestRun before demo; revert removes encrypted-extension files and restores from backup so the environment is ready for another demo.
- **Configurable:** Settings for extension monitoring, rate limiting, entropy analysis, DNS protection (UI); config includes time windows and thresholds.

### Demo Ransomware

- **Educational only:** Simulates ransomware behavior (rename + magic header) only under a single sandbox directory (TestRun).
- **Cordyceps-style:** Uses `.cordyceps` extension and `CORD` magic bytes; compatible with Anton’s extension and behavioral detection.
- **Sandboxed:** Strict path check so it never operates outside the given root folder.
- **Stoppable:** Run as child process by Anton; killed after detection or timeout; revert then restores the folder.

### Integration

- Backend (watcher, detectors, simulators, revert) and frontend (Slint UI) are connected: Dashboard buttons **Run Ransomware Demo** and **Revert Demo** trigger the same backup → run demo → kill → revert logic (through the shared cancellable demo controller or verified restore). Status and activity are shown in the UI.

## Demo Environment Setup

1. Run `cargo build --release`.
2. Optional: create a desktop launcher — macOS: `./build_and_install.sh`; Windows: `build_and_install.bat`.
3. Ensure the `TestRun` folder exists (it is created automatically if missing) and contains sample files for the demo.
4. For a clean repeat demo: use **Revert Demo** or `anton revert` after each run so TestRun is restored for the next demonstration.

See the main [README.md](README.md#build--run-on-macos) for the full macOS build/run/package instructions (native build, Podman/OrbStack containers, `.app`/`.dmg` packaging).
