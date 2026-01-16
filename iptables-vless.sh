#!/bin/bash
# iptables configuration for VLESS blue-green deployment
# Fallback solution for systems without nftables
# Usage: sudo bash iptables-vless.sh [install|switch-a|switch-b|status]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Function to install iptables-persistent
install_iptables() {
    print_info "Installing iptables and persistence tools..."
    
    # Check if iptables-persistent is installed
    if ! dpkg -l | grep -q iptables-persistent; then
        print_info "Installing iptables-persistent package..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
        print_info "✓ Installed iptables-persistent"
    else
        print_info "✓ iptables-persistent already installed"
    fi
    
    # Check if netfilter-persistent is available
    if ! command -v netfilter-persistent &> /dev/null; then
        print_info "Installing netfilter-persistent..."
        apt-get install -y netfilter-persistent
        print_info "✓ Installed netfilter-persistent"
    else
        print_info "✓ netfilter-persistent already installed"
    fi
}

# Function to clear existing VLESS rules
clear_rules() {
    print_info "Clearing existing VLESS redirect rules..."
    
    # Delete any existing redirects on port 443 (don't fail if not exist)
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10080 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10081 2>/dev/null || true
    
    print_info "✓ Cleared old rules"
}

# Function to setup initial rules for Instance A
setup_instance_a() {
    print_info "Setting up port forwarding: 443 -> 10080 (Instance A)..."
    
    # Clear any existing rules
    clear_rules
    
    # Add redirect rule
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10080
    
    # Add security rules (prevent direct external access to internal ports)
    iptables -A INPUT -p tcp --dport 10080 -s 127.0.0.0/8 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 10080 ! -s 127.0.0.0/8 -j DROP 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 10081 -s 127.0.0.0/8 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 10081 ! -s 127.0.0.0/8 -j DROP 2>/dev/null || true
    
    # Save rules
    netfilter-persistent save
    
    print_info "✓ Traffic routed to Instance A (port 10080)"
}

# Function to switch to Instance B
switch_to_b() {
    print_info "Switching traffic to Instance B (port 10081)..."
    
    # Clear existing rules
    clear_rules
    
    # Add redirect to Instance B
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10081
    
    # Save rules
    netfilter-persistent save
    
    print_info "✓ Traffic switched to Instance B (port 10081)"
}

# Function to switch to Instance A
switch_to_a() {
    print_info "Switching traffic to Instance A (port 10080)..."
    
    # Clear existing rules
    clear_rules
    
    # Add redirect to Instance A
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10080
    
    # Save rules
    netfilter-persistent save
    
    print_info "✓ Traffic switched to Instance A (port 10080)"
}

# Function to show current status
show_status() {
    print_info "Current iptables NAT rules for port 443:"
    echo ""
    iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "dpt:443|Chain PREROUTING" || print_warn "No rules found"
    echo ""
    
    # Detect active instance
    if iptables -t nat -L PREROUTING -n | grep -q "redir ports 10080"; then
        print_info "Active Instance: A (port 10080)"
    elif iptables -t nat -L PREROUTING -n | grep -q "redir ports 10081"; then
        print_info "Active Instance: B (port 10081)"
    else
        print_warn "No active redirect rule found"
    fi
}

# Main logic
case "${1:-}" in
    install)
        print_info "Installing iptables-based VLESS routing..."
        install_iptables
        setup_instance_a
        show_status
        print_info "✓ Installation complete - Instance A is active"
        ;;
    switch-a)
        switch_to_a
        show_status
        ;;
    switch-b)
        switch_to_b
        show_status
        ;;
    status)
        show_status
        ;;
    *)
        echo "VLESS iptables Management Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  install    - Install iptables and setup Instance A as active"
        echo "  switch-a   - Switch traffic to Instance A (port 10080)"
        echo "  switch-b   - Switch traffic to Instance B (port 10081)"
        echo "  status     - Show current routing configuration"
        echo ""
        echo "Example:"
        echo "  sudo $0 install"
        echo "  sudo $0 switch-b"
        exit 1
        ;;
esac

exit 0
