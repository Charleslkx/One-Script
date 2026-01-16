#!/bin/bash
# Traffic switching utility for VLESS blue-green deployment
# Supports both nftables and iptables
# Usage: sudo bash switch-traffic.sh [a|b]

set -e

# Colors
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

# Determine which firewall system is in use
detect_firewall() {
    if command -v nft &> /dev/null && systemctl is-active --quiet nftables 2>/dev/null; then
        echo "nftables"
    elif command -v iptables &> /dev/null; then
        echo "iptables"
    else
        echo "none"
    fi
}

# Switch using nftables
switch_nftables() {
    local target=$1
    local port=""
    
    if [ "$target" = "a" ]; then
        port="10080"
        print_step "Switching to Instance A (port 10080) via nftables..."
    elif [ "$target" = "b" ]; then
        port="10081"
        print_step "Switching to Instance B (port 10081) via nftables..."
    else
        print_error "Invalid target: $target"
        exit 1
    fi
    
    # Flush the vless chain
    print_info "Clearing existing redirect rules..."
    nft flush chain nat prerouting_vless 2>/dev/null || {
        print_warn "Chain doesn't exist, creating it..."
        nft add chain nat prerouting_vless
    }
    
    # Add new rule
    print_info "Adding redirect rule: 443 -> $port"
    nft add rule nat prerouting_vless tcp dport 443 counter dnat to :$port
    
    # Persist changes
    print_info "Persisting configuration..."
    nft list ruleset > /etc/nftables.conf
    
    print_info "✓ Traffic switched to Instance ${target^^} (port $port)"
}

# Switch using iptables
switch_iptables() {
    local target=$1
    local port=""
    
    if [ "$target" = "a" ]; then
        port="10080"
        print_step "Switching to Instance A (port 10080) via iptables..."
    elif [ "$target" = "b" ]; then
        port="10081"
        print_step "Switching to Instance B (port 10081) via iptables..."
    else
        print_error "Invalid target: $target"
        exit 1
    fi
    
    # Remove existing rules
    print_info "Clearing existing redirect rules..."
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10080 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10081 2>/dev/null || true
    
    # Add new rule
    print_info "Adding redirect rule: 443 -> $port"
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port $port
    
    # Persist changes
    print_info "Persisting configuration..."
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    else
        print_warn "netfilter-persistent not found, rules may not persist after reboot"
    fi
    
    print_info "✓ Traffic switched to Instance ${target^^} (port $port)"
}

# Show current status
show_status() {
    local fw=$(detect_firewall)
    
    echo ""
    print_info "========================================="
    print_info "Current Routing Status"
    print_info "========================================="
    
    if [ "$fw" = "nftables" ]; then
        print_info "Firewall: nftables"
        echo ""
        nft list chain nat prerouting_vless 2>/dev/null || print_warn "Chain not found"
        
        if nft list ruleset | grep -q "dnat to :10080"; then
            print_info "✓ Active: Instance A (port 10080)"
        elif nft list ruleset | grep -q "dnat to :10081"; then
            print_info "✓ Active: Instance B (port 10081)"
        else
            print_warn "No active redirect found"
        fi
    elif [ "$fw" = "iptables" ]; then
        print_info "Firewall: iptables"
        echo ""
        iptables -t nat -L PREROUTING -n -v | grep -E "dpt:443|Chain PREROUTING" || true
        
        if iptables -t nat -L PREROUTING -n | grep -q "redir ports 10080"; then
            print_info "✓ Active: Instance A (port 10080)"
        elif iptables -t nat -L PREROUTING -n | grep -q "redir ports 10081"; then
            print_info "✓ Active: Instance B (port 10081)"
        else
            print_warn "No active redirect found"
        fi
    else
        print_error "No firewall system detected"
    fi
    
    echo ""
    print_info "Service Status:"
    systemctl is-active vless-instance-a.service &>/dev/null && \
        echo -e "  Instance A: ${GREEN}active${NC}" || echo -e "  Instance A: ${RED}inactive${NC}"
    systemctl is-active vless-instance-b.service &>/dev/null && \
        echo -e "  Instance B: ${GREEN}active${NC}" || echo -e "  Instance B: ${RED}inactive${NC}"
    
    echo ""
    print_info "Port Status:"
    ss -tlnp | grep -q ":10080" && echo -e "  Port 10080: ${GREEN}listening${NC}" || echo -e "  Port 10080: ${RED}not listening${NC}"
    ss -tlnp | grep -q ":10081" && echo -e "  Port 10081: ${GREEN}listening${NC}" || echo -e "  Port 10081: ${RED}not listening${NC}"
    echo ""
}

# Validate target instance is running
validate_instance() {
    local target=$1
    local port=""
    local service=""
    
    if [ "$target" = "a" ]; then
        port="10080"
        service="vless-instance-a.service"
    else
        port="10081"
        service="vless-instance-b.service"
    fi
    
    # Check if service is active
    if ! systemctl is-active --quiet "$service"; then
        print_warn "Warning: $service is not active"
        print_warn "Starting service..."
        systemctl start "$service"
        sleep 2
    fi
    
    # Check if port is listening
    if ! ss -tlnp | grep -q ":$port"; then
        print_error "Instance ${target^^} port $port is not listening"
        print_error "Please check the service: sudo systemctl status $service"
        exit 1
    fi
    
    print_info "✓ Instance ${target^^} is healthy and ready"
}

# Main logic
FIREWALL=$(detect_firewall)

if [ "$FIREWALL" = "none" ]; then
    print_error "No firewall system detected (nftables or iptables required)"
    exit 1
fi

case "${1:-}" in
    a|A)
        print_info "Target: Instance A"
        validate_instance "a"
        
        if [ "$FIREWALL" = "nftables" ]; then
            switch_nftables "a"
        else
            switch_iptables "a"
        fi
        
        show_status
        ;;
    b|B)
        print_info "Target: Instance B"
        validate_instance "b"
        
        if [ "$FIREWALL" = "nftables" ]; then
            switch_nftables "b"
        else
            switch_iptables "b"
        fi
        
        show_status
        ;;
    status)
        show_status
        ;;
    *)
        echo "VLESS Traffic Switching Utility"
        echo ""
        echo "Usage: $0 [target]"
        echo ""
        echo "Targets:"
        echo "  a        - Switch to Instance A (port 10080)"
        echo "  b        - Switch to Instance B (port 10081)"
        echo "  status   - Show current routing status"
        echo ""
        echo "Example:"
        echo "  sudo $0 a"
        echo "  sudo $0 b"
        echo "  sudo $0 status"
        echo ""
        echo "Detected firewall: $FIREWALL"
        exit 1
        ;;
esac

exit 0
