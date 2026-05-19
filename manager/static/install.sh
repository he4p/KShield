#!/usr/bin/env bash
set -euo pipefail

# KShield Agent Installer
# Usage: curl -sSL http://MANAGER:8080/install.sh | sudo bash -s -- --token TOKEN --manager-url http://MANAGER:8080

TOKEN=""
MANAGER_URL=""
BINARY_ONLY=""

usage() {
    cat <<EOF
KShield Agent Installer

Usage: $0 --token <token> --manager-url <url> [--binary-only]

  --token TOKEN         Agent registration token (required)
  --manager-url URL     Manager API URL, e.g. http://192.168.122.1:8080 (required)
  --binary-only         Skip compiling, download pre-built binary if available

The manager URL is where this script was downloaded from.
Get the token from the KShield dashboard under Agents -> Add Agent.
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token) TOKEN="$2"; shift 2 ;;
        --manager-url) MANAGER_URL="$2"; shift 2 ;;
        --binary-only) BINARY_ONLY=1; shift ;;
        --help|-h) usage ;;
        *) echo "Unknown: $1"; usage ;;
    esac
done

if [[ -z "$TOKEN" ]]; then usage; fi
if [[ -z "$MANAGER_URL" ]]; then usage; fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $*"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root. Use: curl ... | sudo bash"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS="$ID"
        OS_VERSION="$VERSION_ID"
    else
        err "Cannot detect OS. Unsupported platform."
    fi
    log "Detected: $OS $OS_VERSION"
}

install_deps() {
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq curl gcc clang llvm make libbpf-dev linux-headers-$(uname -r) libc6-dev pkg-config 2>/dev/null || true
            ;;
        arch|manjaro)
            pacman -Syu --noconfirm --needed curl gcc make clang llvm libbpf linux-headers glibc 2>/dev/null || true
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf install -y curl gcc make clang llvm libbpf-devel kernel-headers glibc-devel 2>/dev/null || true
            else
                yum install -y curl gcc make kernel-headers glibc-devel 2>/dev/null || true
            fi
            ;;
        *)
            warn "Unknown OS: $OS. Attempting to proceed anyway."
            ;;
    esac
}

install_rust() {
    if command -v cargo &>/dev/null; then
        local ver
        ver=$(cargo --version 2>/dev/null | cut -d' ' -f2)
        local major
        major=$(echo "$ver" | cut -d. -f1)
        if [[ "$major" -ge 1 ]] && command -v rustc &>/dev/null; then
            local rust_ver
            rust_ver=$(rustc --version 2>/dev/null | cut -d' ' -f2 | cut -d. -f2)
            if [[ "${rust_ver:-0}" -ge 78 ]]; then
                log "Rust $ver is sufficient."
                return
            fi
        fi
        warn "Rust $ver is too old (need >= 1.78). Installing via rustup..."
    fi

    log "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"

    if ! command -v cargo &>/dev/null; then
        err "Rust installation failed."
    fi
    log "Rust $(rustc --version) installed."
}

build_agent() {
    local base_dir="$HOME/kshield-install"
    rm -rf "$base_dir"
    mkdir -p "$base_dir"

    # Ensure cargo is in PATH (rustup installs to $HOME/.cargo/bin)
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"

    log "Downloading agent source from $MANAGER_URL/agent-src.tar.gz ..."
    curl -sSL -o "$base_dir/agent-src.tar.gz" "$MANAGER_URL/agent-src.tar.gz" || \
        err "Failed to download agent source. Is the manager running at $MANAGER_URL?"

    cd "$base_dir"
    tar xzf agent-src.tar.gz

    if [[ ! -f "agent/build_bpf.sh" ]]; then
        err "Agent source archive is missing build files."
    fi

    log "Building BPF programs..."
    cd agent && bash build_bpf.sh

    log "Compiling agent (this may take a few minutes)..."
    # Try with lockfile, fall back to generate a compatible one
    if ! cargo build --release 2>/dev/null; then
        warn "Initial build failed, regenerating lockfile for this Rust version..."
        rm -f Cargo.lock
        if ! cargo generate-lockfile 2>/dev/null; then
            warn "cargo generate-lockfile failed, trying cargo update..."
            cargo update 2>/dev/null || true
        fi
        cargo build --release 2>&1 | tail -5 || err "Build failed. Your Rust version may be too old."
    fi

    if [[ ! -f "target/release/kshield-agent" ]]; then
        err "Build failed. Check output above."
    fi

    log "Build complete."
}

install_agent() {
    local base_dir="$HOME/kshield-install/agent"
    local install_dir="/opt/kshield-agent"

    mkdir -p "$install_dir"

    cp "$base_dir/target/release/kshield-agent" "$install_dir/kshield-agent"
    cp "$base_dir/bpf/kshield.bpf.o" "$install_dir/kshield.bpf.o"
    chmod +x "$install_dir/kshield-agent"

    log "Agent binary installed to $install_dir"
}

create_service() {
    local service_file="/etc/systemd/system/kshield-agent.service"
    cat > "$service_file" <<SERVICEOF
[Unit]
Description=KShield eBPF Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/kshield-agent/kshield-agent \\
  --manager-url $MANAGER_URL \\
  --agent-token $TOKEN \\
  --bpf-object /opt/kshield-agent/kshield.bpf.o
Restart=always
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICEOF

    systemctl daemon-reload
    systemctl enable kshield-agent
    systemctl restart kshield-agent

    log "Systemd service installed and started."
}

verify() {
    sleep 3
    if systemctl is-active --quiet kshield-agent; then
        log "Agent is running!"
        systemctl status kshield-agent --no-pager -l | head -12
    else
        warn "Agent may not have started. Check logs:"
        warn "  journalctl -u kshield-agent -n 30"
        warn "  cat /opt/kshield-agent/agent.log"
    fi
}

# ---- main ----

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║       KShield Agent Installer        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

require_root
detect_os
install_deps
install_rust
build_agent
install_agent
create_service
verify

echo ""
log "Installation complete."
log "Check the dashboard at $MANAGER_URL to see your agent."
echo ""
