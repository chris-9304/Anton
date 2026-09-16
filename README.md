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
# Start monitoring
cargo run --bin anton -- run

# Run ransomware simulators (for testing)
cargo run --bin anton -- simulate old      # Old-style ransomware
cargo run --bin anton -- simulate modern  # Modern ransomware
cargo run --bin anton -- simulate wiper   # Wiper malware

# Reset test files
cargo run --bin anton -- reset
```

## Architecture

### Backend Modules
- `config.rs`: Configuration management
- `models.rs`: Data models (events, threats, detections)
- `detectors.rs`: Detection analyzers (frequency, extension, behavior, entropy)
- `ai.rs`: AI classification engine
- `watcher.rs`: File system watcher
- `crypto.rs`: Cryptographic utilities
- `recovery.rs`: File recovery and backup
- `simulators.rs`: Test ransomware simulators
- `api_server.rs`: HTTP API server

### Frontend Structure
- `src/App.jsx`: Main application component
- `src/services/api.js`: API client
- Components: Dashboard, Settings, History, Scan Activity

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

## License

Professional anti-ransomware system - All rights reserved
