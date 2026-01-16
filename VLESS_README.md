# VLESS Blue-Green Deployment

## Introduction

VLESS Blue-Green is a high-availability deployment system for VLESS+Vision+Reality protocol, providing zero-downtime updates and automatic failover capabilities. The system has been integrated into the main.sh menu interface for simplified management.

## Features

- **Dual-instance deployment**: Two independent VLESS instances running on ports 10080 and 10081
- **Automatic health monitoring**: Continuous health checks with automatic failover
- **Zero-downtime switching**: Instant traffic routing between instances
- **Boot persistence**: Services automatically start after system reboot
- **Resource control**: Memory limits, CPU weights, and file descriptor limits per instance
- **Firewall integration**: Support for both nftables (modern) and iptables (legacy)

## Architecture

```
External Traffic (Port 443)
         ↓
   nftables/iptables
         ↓
   Active Instance (10080 or 10081)
         ↓
   Standby Instance (monitored)
```

### Components

1. **Instance A** (vless-instance-a.service)
   - Port: 10080
   - Default active instance
   - Systemd service with auto-restart

2. **Instance B** (vless-instance-b.service)
   - Port: 10081
   - Standby instance
   - Systemd service with auto-restart

3. **Monitor Service** (vless-monitor.service)
   - Health check interval: 30 seconds
   - Failure threshold: 3 consecutive failures (90 seconds)
   - Automatic traffic failover
   - Syslog integration

4. **Traffic Controller**
   - Port forwarding: 443 → 10080/10081
   - Atomic rule updates (nftables)
   - Persistent configuration

## Installation

### Quick Start

```bash
sudo bash main.sh
# Select: 11 (VLESS Blue-Green)
# Select: 1 (Install)
```

The installation process takes 30-60 seconds and includes:

1. System dependency installation (curl, wget, unzip, netcat, jq)
2. Xray-core binary installation from GitHub
3. System user creation (vless:vless)
4. Directory structure setup (/etc/vless, /var/log/vless)
5. Configuration generation (UUID and Reality keys)
6. Systemd service installation
7. Management script installation
8. Firewall configuration (nftables or iptables)
9. Service startup and auto-start enablement

### Post-Installation

After installation completes:

- Both instances will be running
- Monitor service will be active
- Port 443 will route to Instance A (10080) by default
- Services will auto-start on system reboot
- UUID will be displayed for client configuration

## Usage

### Menu Navigation

Access the VLESS management interface:

```bash
sudo bash main.sh
# Select: 11
```

### Available Operations

| Option | Operation | Description |
|--------|-----------|-------------|
| 1 | Switch to Instance A | Route traffic to port 10080 |
| 2 | Switch to Instance B | Route traffic to port 10081 |
| 3 | View detailed status | Display routing, services, and ports |
| 4 | View monitor logs | Real-time health check logs |
| 5 | Start all services | Start both instances and monitor |
| 6 | Stop all services | Stop all three services |
| 7 | Restart all services | Restart with configuration reload |
| 8 | View configuration | Display UUID and file paths |
| 9 | Uninstall system | Complete removal of all components |
| 10 | Back to main menu | Return to main.sh menu |

### Traffic Switching

Switch between instances with zero downtime:

```bash
# Via menu
main.sh → 11 → 1 (Instance A) or 2 (Instance B)

# Via command line
sudo /usr/local/bin/switch-traffic.sh a
sudo /usr/local/bin/switch-traffic.sh b
sudo /usr/local/bin/switch-traffic.sh status
```

Switching takes less than 2 seconds with no dropped connections.

### Service Management

Control services through menu or systemctl:

```bash
# Via menu
main.sh → 11 → 5/6/7

# Via systemctl
sudo systemctl start vless-instance-a.service
sudo systemctl stop vless-instance-a.service
sudo systemctl restart vless-instance-a.service
sudo systemctl status vless-instance-a.service
```

### Monitoring

View real-time health monitoring:

```bash
# Via menu
main.sh → 11 → 4

# Via journalctl
sudo journalctl -u vless-monitor.service -f
```

Monitor logs show:
- Health check results every 30 seconds
- Automatic failover events
- Service restart attempts
- Memory limit warnings

## Configuration

### File Locations

```
/etc/vless/
  ├── config-a.json          # Instance A configuration
  └── config-b.json          # Instance B configuration

/var/log/vless/             # Log directory (if file logging enabled)

/usr/local/bin/
  ├── xray                   # Xray-core binary
  ├── switch-traffic.sh      # Traffic switching script
  └── monitor-vless.sh       # Health monitoring script

/etc/systemd/system/
  ├── vless-instance-a.service
  ├── vless-instance-b.service
  └── vless-monitor.service
```

### Editing Configuration

Modify instance configurations:

```bash
sudo nano /etc/vless/config-a.json
sudo nano /etc/vless/config-b.json

# Apply changes
main.sh → 11 → 7 (Restart services)
```

### Viewing Configuration

Display current configuration:

```bash
main.sh → 11 → 8
```

Shows:
- Generated UUID
- Configuration file paths
- Port assignments
- Active instance

## Auto-Start Configuration

### Enabling Auto-Start

Services are automatically enabled during installation:

```bash
systemctl enable vless-instance-a.service
systemctl enable vless-instance-b.service
systemctl enable vless-monitor.service
```

This creates symlinks in `/etc/systemd/system/multi-user.target.wants/`.

### Verification

Check auto-start status:

```bash
systemctl is-enabled vless-instance-a.service
systemctl is-enabled vless-instance-b.service
systemctl is-enabled vless-monitor.service
```

Expected output: `enabled` for all three services.

### Startup Order

After system reboot, services start in this order:

1. vless-instance-a.service
2. vless-instance-b.service
3. vless-monitor.service (depends on both instances)

### Testing Reboot Persistence

```bash
sudo reboot

# After reboot
sudo systemctl status vless-instance-a.service
sudo systemctl status vless-instance-b.service
sudo systemctl status vless-monitor.service

# All should show "active (running)"
```

## Automatic Failover

### Health Check Process

The monitor service performs health checks every 30 seconds:

1. **Service status check**: Verify systemd service is active
2. **Port listening check**: Verify port is accessible
3. **Connection test**: Attempt TCP connection
4. **Memory check**: Verify memory limits not exceeded
5. **Process check**: Verify main process exists

### Failure Detection

- Check interval: 30 seconds
- Failure threshold: 3 consecutive failures
- Total detection time: ~90 seconds

### Failover Process

When active instance fails:

1. Monitor detects failure (after 3 checks)
2. Verifies standby instance is healthy
3. Executes traffic switch (nftables/iptables update)
4. Logs failover event to syslog
5. Attempts to restart failed instance

Failover completes in less than 5 seconds after detection.

### Monitoring Failover

Watch monitor logs for failover events:

```bash
sudo journalctl -u vless-monitor.service -f
```

Failover log example:
```
FAILOVER INITIATED: Switching from Instance a to Instance b
Executing traffic switch to Instance b...
FAILOVER COMPLETE: Traffic now routed to Instance b
Attempting to restart failed instance...
```

## Troubleshooting

### Services Won't Start

**Check service status:**
```bash
sudo systemctl status vless-instance-a.service
sudo journalctl -u vless-instance-a.service -n 50
```

**Common causes:**
- Port already in use
- Configuration syntax error
- Missing Xray binary
- Permission issues

**Solutions:**
```bash
# Check port availability
sudo ss -tlnp | grep -E '10080|10081|443'

# Validate configuration
/usr/local/bin/xray test -c /etc/vless/config-a.json

# Check binary
ls -la /usr/local/bin/xray

# Restart service
sudo systemctl restart vless-instance-a.service
```

### Traffic Not Routing

**Check firewall rules:**
```bash
# nftables
sudo nft list ruleset | grep dnat

# iptables
sudo iptables -t nat -L PREROUTING -n -v
```

**Re-apply routing:**
```bash
sudo /usr/local/bin/switch-traffic.sh a
sudo /usr/local/bin/switch-traffic.sh status
```

### Auto-Start Not Working

**Verify services are enabled:**
```bash
systemctl is-enabled vless-instance-a.service
```

**If disabled, re-enable:**
```bash
sudo systemctl enable vless-instance-a.service
sudo systemctl enable vless-instance-b.service
sudo systemctl enable vless-monitor.service
```

**Check boot logs:**
```bash
sudo journalctl -b -u vless-instance-a.service
```

### Monitor Not Failing Over

**Check monitor service:**
```bash
sudo systemctl status vless-monitor.service
sudo journalctl -u vless-monitor.service -n 50
```

**Restart monitor:**
```bash
sudo systemctl restart vless-monitor.service
```

### Memory Issues

**Check memory usage:**
```bash
systemctl show vless-instance-a.service -p MemoryMax -p MemoryCurrent
```

**Adjust limits in service file:**
```bash
sudo nano /etc/systemd/system/vless-instance-a.service
# Modify MemoryMax= value
sudo systemctl daemon-reload
sudo systemctl restart vless-instance-a.service
```

## Uninstallation

### Complete Removal

Remove all VLESS Blue-Green components:

```bash
sudo bash main.sh
# Select: 11 → 9
# Confirm: y
```

### What Gets Removed

- Systemd service files
- Configuration files (/etc/vless)
- Log files (/var/log/vless)
- Management scripts
- Firewall rules
- Auto-start configuration

### What Is Preserved

- Xray-core binary (may be used by other services)
- System user 'vless' (may be used by other services)

### Manual Cleanup

If additional cleanup is needed:

```bash
# Remove Xray binary
sudo rm /usr/local/bin/xray

# Remove vless user
sudo userdel vless

# Remove geoip/geosite data
sudo rm -rf /usr/local/share/xray
```

## Security Considerations

### Service Hardening

All services run with security restrictions:

- **Non-root user**: Services run as `vless:vless`
- **PrivateTmp**: Isolated /tmp directories
- **NoNewPrivileges**: Prevents privilege escalation
- **MemoryMax**: Prevents memory exhaustion attacks
- **LimitNOFILE**: Prevents file descriptor exhaustion
- **ProtectSystem**: Read-only system directories
- **ProtectHome**: No access to home directories

### File Permissions

- Configuration files: 600 (owner read/write only)
- Service files: 644 (owner write, all read)
- Scripts: 755 (owner write, all execute)
- Log directory: 755 (owner write, vless group read)

### Firewall Rules

Internal ports (10080, 10081) should only be accessible from localhost. External traffic should only reach port 443.

### Network Security

Consider additional protections:
- AppArmor/SELinux profiles
- Connection rate limiting
- Fail2ban integration
- IP whitelisting

## Performance Tuning

### Resource Limits

Adjust in service files as needed:

```ini
MemoryMax=512M          # Maximum memory per instance
MemoryHigh=400M         # Soft warning threshold
CPUWeight=200           # CPU scheduling priority
CPUQuota=50%            # Maximum CPU usage
LimitNOFILE=65535       # File descriptor limit
Nice=-5                 # Process priority
```

### Connection Limits

Increase file descriptor limit for high-traffic scenarios:

```bash
sudo nano /etc/systemd/system/vless-instance-a.service
# Modify LimitNOFILE=65535 to higher value
sudo systemctl daemon-reload
sudo systemctl restart vless-instance-a.service
```

### Monitoring Interval

Adjust health check frequency:

```bash
sudo nano /usr/local/bin/monitor-vless.sh
# Modify CHECK_INTERVAL=30
sudo systemctl restart vless-monitor.service
```

## Client Configuration

### Connection Parameters

Use these parameters in VLESS clients:

```
Protocol: VLESS
Address: <server-ip>
Port: 443
UUID: <from-installation>
Flow: xtls-rprx-vision
Security: reality
SNI: www.microsoft.com
Public Key: <from-reality-config>
Short ID: (leave empty)
```

### Retrieving UUID

View configuration to get UUID:

```bash
main.sh → 11 → 8

# Or directly
sudo grep '"id"' /etc/vless/config-a.json | head -1
```

### Testing Connection

Test VLESS connection:

```bash
# From client machine
curl -v --proxy socks5h://127.0.0.1:1080 https://www.google.com
```

## Advanced Usage

### Zero-Downtime Updates

Update configurations without service interruption:

1. Edit Instance B configuration while A is active
2. Switch traffic to B
3. Edit Instance A configuration
4. Switch traffic back to A

```bash
# Update B (A is active)
sudo nano /etc/vless/config-b.json
main.sh → 11 → 2  # Switch to B

# Update A (B is active)
sudo nano /etc/vless/config-a.json
main.sh → 11 → 1  # Switch to A
```

### Manual Traffic Control

Control traffic routing directly:

```bash
# nftables
sudo nft flush chain nat prerouting_vless
sudo nft add rule nat prerouting_vless tcp dport 443 counter dnat to :10080
sudo nft list ruleset > /etc/nftables.conf

# iptables
sudo iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10081
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 10080
sudo netfilter-persistent save
```

### Custom Monitor Checks

Modify health check logic:

```bash
sudo nano /usr/local/bin/monitor-vless.sh
# Edit check_instance_health() function
sudo systemctl restart vless-monitor.service
```

### Log Management

Configure log retention:

```bash
# Limit journal size
sudo journalctl --vacuum-size=100M
sudo journalctl --vacuum-time=7d

# View specific time range
sudo journalctl -u vless-monitor.service --since "1 hour ago"
```

## Integration Details

### Modified Components

**main.sh additions:**
- Menu option 11: VLESS Blue-Green
- `check_vless_installed()`: Installation detection
- `install_vless_bluegreen()`: Installation automation
- `uninstall_vless_bluegreen()`: Removal automation
- `vless_bluegreen_menu()`: Management interface

Total additions: ~850 lines of code

### Dependencies

Required packages (auto-installed):
- curl
- wget
- unzip
- netcat-openbsd
- jq
- systemd

Required services:
- nftables (preferred) or iptables
- systemd (init system)

### Compatibility

**Operating Systems:**
- Ubuntu 18.04+
- Debian 10+
- CentOS 8+ / Rocky Linux 8+
- Fedora 30+

**Architectures:**
- x86_64 (amd64)
- aarch64 (arm64)
- armv7l (arm32)

## Documentation

### Available Documents

| Document | Purpose |
|----------|---------|
| README.md (this file) | Complete reference guide |
| VLESS_QUICKREF.md | Quick reference card |
| VLESS_CHECKLIST.md | Installation verification |
| VLESS_DOCS_INDEX.md | Documentation index |

### Getting Help

For issues or questions:

1. Check troubleshooting section above
2. Review relevant documentation
3. Check service logs with `journalctl`
4. Verify configuration with `xray test`

## License

This project is provided as-is without warranty. Use at own risk.

## Credits

- Xray-core: https://github.com/XTLS/Xray-core
- Original inspiration: mack-a/v2ray-agent
