#!/bin/bash
# Health monitoring and auto-failover script for VLESS blue-green deployment
# This script continuously monitors both instances and automatically switches traffic if needed
# Logs to syslog for integration with monitoring systems

# Configuration
CHECK_INTERVAL=30          # Check every 30 seconds
FAILURE_THRESHOLD=3        # Require 3 consecutive failures before failover
CONNECTION_TIMEOUT=3       # Timeout for port checks (seconds)
LOG_TAG="vless-monitor"

# State file to track failures
STATE_DIR="/var/run/vless-monitor"
FAILURE_COUNT_FILE="$STATE_DIR/failure_count"
ACTIVE_INSTANCE_FILE="$STATE_DIR/active_instance"

# Create state directory
mkdir -p "$STATE_DIR"

# Initialize state files if they don't exist
[ ! -f "$FAILURE_COUNT_FILE" ] && echo "0" > "$FAILURE_COUNT_FILE"
[ ! -f "$ACTIVE_INSTANCE_FILE" ] && echo "a" > "$ACTIVE_INSTANCE_FILE"

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    logger -t "$LOG_TAG" -p "daemon.$level" "$message"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $message"
}

# Get current active instance from firewall rules
get_active_instance() {
    # Try nftables first
    if command -v nft &> /dev/null && systemctl is-active --quiet nftables 2>/dev/null; then
        if nft list ruleset 2>/dev/null | grep -q "dnat to :10080"; then
            echo "a"
            return
        elif nft list ruleset 2>/dev/null | grep -q "dnat to :10081"; then
            echo "b"
            return
        fi
    fi
    
    # Try iptables
    if command -v iptables &> /dev/null; then
        if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports 10080"; then
            echo "a"
            return
        elif iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports 10081"; then
            echo "b"
            return
        fi
    fi
    
    # Unknown state
    echo "unknown"
}

# Check if a specific instance is healthy
check_instance_health() {
    local instance=$1
    local port=""
    local service=""
    
    if [ "$instance" = "a" ]; then
        port="10080"
        service="vless-instance-a.service"
    elif [ "$instance" = "b" ]; then
        port="10081"
        service="vless-instance-b.service"
    else
        return 1
    fi
    
    local healthy=true
    
    # Check 1: Service is active
    if ! systemctl is-active --quiet "$service"; then
        log "warning" "Instance $instance: service $service is not active"
        healthy=false
    fi
    
    # Check 2: Port is listening
    if ! timeout "$CONNECTION_TIMEOUT" nc -z localhost "$port" 2>/dev/null; then
        log "warning" "Instance $instance: port $port is not responding"
        healthy=false
    fi
    
    # Check 3: Memory limit not hit (check for OOM kills in recent logs)
    if journalctl -u "$service" --since "1 minute ago" 2>/dev/null | grep -q "memory.max"; then
        log "error" "Instance $instance: memory limit hit (potential OOM)"
        healthy=false
    fi
    
    # Check 4: Log explosion detection (> 1000 lines in last 5 minutes)
    local log_count=$(journalctl -u "$service" --since "5 minutes ago" 2>/dev/null | wc -l)
    if [ "$log_count" -gt 1000 ]; then
        log "warning" "Instance $instance: log explosion detected ($log_count lines in 5 minutes)"
        # Note: This is a warning, not a failure - might be legitimate traffic spike
    fi
    
    # Check 5: Process exists and is responsive
    if ! systemctl show "$service" -p MainPID | grep -q "MainPID=[1-9]"; then
        log "error" "Instance $instance: no main process found"
        healthy=false
    fi
    
    if [ "$healthy" = true ]; then
        return 0
    else
        return 1
    fi
}

# Perform failover to standby instance
perform_failover() {
    local from_instance=$1
    local to_instance=$2
    
    log "alert" "FAILOVER INITIATED: Switching from Instance $from_instance to Instance $to_instance"
    
    # Verify target instance is healthy before switching
    if ! check_instance_health "$to_instance"; then
        log "critical" "FAILOVER ABORTED: Target instance $to_instance is also unhealthy!"
        log "critical" "BOTH INSTANCES DOWN - Manual intervention required!"
        return 1
    fi
    
    # Perform the switch
    log "info" "Executing traffic switch to Instance $to_instance..."
    
    if ! /usr/local/bin/switch-traffic.sh "$to_instance" >> /var/log/vless-monitor.log 2>&1; then
        log "critical" "FAILOVER FAILED: Unable to switch traffic!"
        return 1
    fi
    
    # Update state
    echo "$to_instance" > "$ACTIVE_INSTANCE_FILE"
    echo "0" > "$FAILURE_COUNT_FILE"
    
    log "alert" "FAILOVER COMPLETE: Traffic now routed to Instance $to_instance"
    
    # Try to restart the failed instance
    local from_service=""
    if [ "$from_instance" = "a" ]; then
        from_service="vless-instance-a.service"
    else
        from_service="vless-instance-b.service"
    fi
    
    log "info" "Attempting to restart failed instance: $from_service"
    systemctl restart "$from_service" || log "error" "Failed to restart $from_service"
    
    return 0
}

# Main monitoring loop
log "info" "VLESS Monitor started - checking every ${CHECK_INTERVAL}s"
log "info" "Failure threshold: $FAILURE_THRESHOLD consecutive failures"

while true; do
    # Determine current active instance
    ACTIVE=$(get_active_instance)
    
    if [ "$ACTIVE" = "unknown" ]; then
        log "error" "Cannot determine active instance - skipping this check"
        sleep "$CHECK_INTERVAL"
        continue
    fi
    
    # Determine standby instance
    if [ "$ACTIVE" = "a" ]; then
        STANDBY="b"
    else
        STANDBY="a"
    fi
    
    # Check active instance health
    if check_instance_health "$ACTIVE"; then
        # Active instance is healthy - reset failure counter
        CURRENT_FAILURES=$(cat "$FAILURE_COUNT_FILE")
        if [ "$CURRENT_FAILURES" -gt 0 ]; then
            log "info" "Instance $ACTIVE recovered - resetting failure counter"
            echo "0" > "$FAILURE_COUNT_FILE"
        fi
    else
        # Active instance is unhealthy - increment failure counter
        CURRENT_FAILURES=$(cat "$FAILURE_COUNT_FILE")
        CURRENT_FAILURES=$((CURRENT_FAILURES + 1))
        echo "$CURRENT_FAILURES" > "$FAILURE_COUNT_FILE"
        
        log "warning" "Instance $ACTIVE health check failed ($CURRENT_FAILURES/$FAILURE_THRESHOLD)"
        
        # Check if we've hit the threshold
        if [ "$CURRENT_FAILURES" -ge "$FAILURE_THRESHOLD" ]; then
            log "error" "Instance $ACTIVE has failed $FAILURE_THRESHOLD consecutive checks"
            perform_failover "$ACTIVE" "$STANDBY"
        fi
    fi
    
    # Also check standby instance (for informational purposes)
    if check_instance_health "$STANDBY"; then
        log "debug" "Standby Instance $STANDBY is healthy and ready"
    else
        log "warning" "Standby Instance $STANDBY is unhealthy - failover may not be possible"
    fi
    
    # Wait before next check
    sleep "$CHECK_INTERVAL"
done
