<a href="https://picogrid.com">
   <div align="center">
      <img src="https://cdn.sanity.io/images/zv22ki6f/production/6739d71840bea37797572f984f1c86337069d971-800x75.png" alt="Picogrid Logo" width="600"/>
   </div>
</a>

# Legion System Authentication

[![Build and Release](https://github.com/picogrid/legion-system-auth/actions/workflows/build.yml/badge.svg)](https://github.com/picogrid/legion-system-auth/actions/workflows/build.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/picogrid/legion-system-auth)](https://go.dev/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/picogrid/legion-system-auth)](https://github.com/picogrid/legion-system-auth/releases/latest)

A standalone authentication service for Legion integrations on edge devices, development machines, and other systems. This service handles OAuth2 authentication, token lifecycle management (automatic refreshes), and terminal entity registration.

For comprehensive API details, please refer to the [Legion API Documentation](https://docs.picogrid.com/reference/start).

## Features

- **OAuth2 PKCE Flow:** Secure authentication without hardcoded credentials.
- **Automatic Token Management:** Monitors and refreshes access tokens automatically.
- **Headless Support:** Supports authentication flows on headless devices via local callbacks.
- **Service Integration:** Built-in support for installing as a system service:
  - **Linux:** Systemd
  - **macOS:** Launchd

## Installation

### Quick Install (Recommended)

Install the latest release with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/picogrid/legion-system-auth/main/install.sh | bash
```

The script will automatically detect your platform and prompt for sudo if needed.

### Build from Source

#### Prerequisites

- Go 1.23 or later
- Make

#### Build and Install

1. **Clone the repository:**
   ```bash
   git clone https://github.com/picogrid/legion-system-auth.git
   cd legion-system-auth
   ```

2. **Build the binary:**
   ```bash
   make build
   ```

3. **Install globally (optional):**
   ```bash
   sudo make install
   ```
   This installs `legion-auth` to `/usr/local/bin`.

## Usage

### 1. Initial Setup

Run the interactive setup wizard to authenticate and configure the integration.

```bash
legion-auth setup
```

**Options:**
- `--create-entity`: Prompts to create a Terminal entity in Legion during setup.
- `--storage-path <dir>`: Custom directory to store tokens and config (Default: `/etc/picogrid/auth`).

**Example:**
```bash
legion-auth setup --create-entity
```

### 2. Install as a Service (Recommended)

To ensure the token monitor runs automatically and keeps credentials fresh, you can install as either a **user-level** or **system-level** service:

#### User-Level Service (No sudo required)

Runs as your user account and starts automatically on login:

```bash
legion-auth install-service --user
```

**Benefits:**
- No sudo required
- Runs with your user permissions
- Starts automatically when you log in
- Stores credentials in your home directory

#### System-Level Service (Requires sudo)

Runs at system startup with specified user permissions:

```bash
sudo legion-auth install-service
```

This will:
- Generate the appropriate service file (`systemd` unit or `launchd` plist)
- Enable the service to start at boot
- Start the service immediately

**Custom options:**
```bash
# Custom storage path
legion-auth install-service --user --storage-path ~/.config/legion-auth

# System-level with specific user (Linux only)
sudo legion-auth install-service --service-user myuser
```

### 3. Uninstall Service

To remove an installed service:

```bash
# Uninstall user-level service
legion-auth uninstall-service --user

# Uninstall system-level service (requires sudo)
sudo legion-auth uninstall-service
```

This will:
- Stop the running service
- Disable it from starting automatically
- Remove the service configuration file

### 4. Manual Execution

You can run the monitor process manually (foreground):

```bash
legion-auth
```

## Configuration

The service stores its data in `/etc/picogrid/auth` by default.
- `oauth_config.json`: Integration settings.
- `access_token.json`: Current active tokens.
- `refresh_token.json`: Long-lived refresh token.
- `terminal_entity.json`: Device metadata (if entity creation was used).

## Security & Verification

All release binaries include SHA256 checksum files (`.sha256`) for integrity verification.

### Verifying Checksums

```bash
# Download binary and checksum
curl -LO https://github.com/picogrid/legion-system-auth/releases/latest/download/legion-auth-linux-amd64
curl -LO https://github.com/picogrid/legion-system-auth/releases/latest/download/legion-auth-linux-amd64.sha256

# Verify
sha256sum -c legion-auth-linux-amd64.sha256
```

The install script automatically verifies checksums when available.

## Development

### Building
- **Build:** `make build` - Build the binary with version info
- **Clean:** `make clean` - Remove build artifacts

### Quality Checks
- **Test:** `make test` - Run tests with race detection and coverage
- **Lint:** `make lint` - Run golangci-lint
- **Security:** `make security` - Run gosec security scanner
- **Check All:** `make check` - Run all checks (fmt, vet, lint, security, test)

### Installation
- **Install:** `make install` - Install binary to /usr/local/bin
- **Install Service:** `sudo make install-service` - Install as system service

### Help
- **Help:** `make help` - Show all available make targets