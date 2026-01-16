#!/bin/bash
# nftables setup script for VLESS blue-green deployment
# This script installs nftables and configures port forwarding
# Usage: sudo bash setup-nftables.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_step "Installing nftables..."

# Check if nftables is installed
if ! command -v nft &> /dev/null; then
    print_info "Installing nftables package..."
    apt-get update
    apt-get install -y nftables
    print_info "✓ Installed nftables"
else
    print_info "✓ nftables already installed ($(nft --version))"
fi

print_step "Configuring nftables..."

# Backup existing configuration if present
if [ -f /etc/nftables.conf ]; then
    print_warn "Backing up existing /etc/nftables.conf to /etc/nftables.conf.backup"
    cp /etc/nftables.conf /etc/nftables.conf.backup.$(date +%Y%m%d_%H%M%S)
fi

# Copy our configuration
print_info "Installing VLESS nftables configuration..."
if [ -f "$(dirname "$0")/nftables-vless.conf" ]; then
    cp "$(dirname "$0")/nftables-vless.conf" /etc/nftables.conf
    print_info "✓ Configuration file installed"
else
    print_error "nftables-vless.conf not found in current directory"
    exit 1
fi

print_step "Stopping conflicting services..."

# Stop and disable iptables if present to avoid conflicts
if systemctl is-active --quiet iptables 2>/dev/null; then
    print_info "Stopping iptables service..."
    systemctl stop iptables
    systemctl disable iptables
    print_info "✓ iptables service disabled"
fi

# Disable ufw if active (it uses iptables)
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    print_warn "UFW is active - disabling to prevent conflicts with nftables"
    ufw disable
    print_info "✓ UFW disabled"
fi

print_step "Loading nftables rules..."

# Load the configuration
nft -f /etc/nftables.conf
print_info "✓ nftables rules loaded"

# Enable and start nftables service
print_step "Enabling nftables service..."
systemctl enable nftables
systemctl restart nftables
print_info "✓ nftables service enabled and started"

print_step "Verifying configuration..."

# Show current ruleset
echo ""
print_info "Current NAT rules:"
nft list chain nat prerouting_vless 2>/dev/null || print_warn "Chain not found - check configuration"

# Verify redirect rule
if nft list ruleset | grep -q "dnat to :10080"; then
    print_info "✓ Traffic is routed to Instance A (port 10080)"
elif nft list ruleset | grep -q "dnat to :10081"; then
    print_info "✓ Traffic is routed to Instance B (port 10081)"
else
    print_warn "No redirect rule found - please verify configuration"
fi

echo ""
print_info "========================================="
print_info "nftables setup complete!"
print_info "========================================="
echo ""
print_info "Default routing: 443 -> 10080 (Instance A)"
echo ""
print_info "To switch traffic:"
echo "  Instance A: sudo bash switch-traffic.sh a"
echo "  Instance B: sudo bash switch-traffic.sh b"
echo ""
print_info "To view current rules:"
echo "  sudo nft list ruleset"
echo ""
print_info "To manually edit rules:"
echo "  sudo nft flush chain nat prerouting_vless"
echo "  sudo nft add rule nat prerouting_vless tcp dport 443 counter dnat to :10081"
echo "  sudo nft list ruleset > /etc/nftables.conf  # Persist changes"

exit 0
