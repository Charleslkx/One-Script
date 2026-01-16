# VLESS Blue-Green Quick Reference

## Quick Start

```bash
sudo bash main.sh
# Select: 11 (VLESS Blue-Green)
# Select: 1 (Install)
```

Installation time: 30-60 seconds

## Menu Structure

### Main Menu
```
11. VLESS Blue-Green (HA monitoring & failover)
```

### VLESS Submenu
```
1.  Switch to Instance A (10080)
2.  Switch to Instance B (10081)
3.  View detailed status
4.  View monitor logs
5.  Start all services
6.  Stop all services
7.  Restart all services
8.  View configuration
9.  Uninstall system
10. Back to main menu
```

## Installed Components

| Component | Location | Auto-Start |
|-----------|----------|------------|
| Xray-core | `/usr/local/bin/xray` | N/A |
| Instance A Config | `/etc/vless/config-a.json` | N/A |
| Instance B Config | `/etc/vless/config-b.json` | N/A |
| Instance A Service | systemd | ✅ |
| Instance B Service | systemd | ✅ |
| Monitor Service | systemd | ✅ |
| Switch Script | `/usr/local/bin/switch-traffic.sh` | N/A |
| Monitor Script | `/usr/local/bin/monitor-vless.sh` | N/A |
| Port Forwarding | nftables/iptables (443→10080) | ✅ |

## Common Operations

### Install
```
main.sh → 11 → 1
```

### Switch Traffic
```
main.sh → 11 → 1 (to A) or 2 (to B)
```

### View Status
```
main.sh → 11 → 3
```

### Check Logs
```
main.sh → 11 → 4
```

### Restart
```
main.sh → 11 → 7
```

### Uninstall
```
main.sh → 11 → 9 → y
```

## Important Files

```bash
# Configuration
/etc/vless/config-a.json
/etc/vless/config-b.json

# Services
/etc/systemd/system/vless-instance-a.service
/etc/systemd/system/vless-instance-b.service
/etc/systemd/system/vless-monitor.service

# Scripts
/usr/local/bin/switch-traffic.sh
/usr/local/bin/monitor-vless.sh
```

## Command Line

### Traffic Control
```bash
sudo /usr/local/bin/switch-traffic.sh a      # Switch to A
sudo /usr/local/bin/switch-traffic.sh b      # Switch to B
sudo /usr/local/bin/switch-traffic.sh status # Status
```

### Service Control
```bash
sudo systemctl {start|stop|restart|status} vless-instance-a.service
```

### Logs
```bash
sudo journalctl -u vless-monitor.service -f
sudo journalctl -u vless-instance-a.service -n 50
```

## Troubleshooting

### Service Issues
```bash
sudo systemctl status vless-instance-a.service
/usr/local/bin/xray test -c /etc/vless/config-a.json
```

### Port Conflicts
```bash
sudo ss -tlnp | grep -E '10080|10081|443'
```

### Firewall
```bash
sudo nft list ruleset | grep dnat
sudo /usr/local/bin/switch-traffic.sh status
```

### Auto-Start
```bash
systemctl is-enabled vless-instance-a.service
sudo systemctl enable vless-instance-a.service
sudo journalctl -b -u vless-instance-a.service
```

## Architecture

```
[Port 443] → [Firewall] → [Instance A: 10080 or Instance B: 10081]
                           [Monitor: 30s checks, 90s failover]
```

## Performance

- Memory: 100-200MB per instance
- CPU: 5-10% idle, 20-50% active
- Failover: < 2 seconds
- Health check: 30 seconds
- Failure threshold: 3 checks (90s)

## Client Config

```
Protocol: VLESS
Address: <server-ip>
Port: 443
UUID: <from installation>
Flow: xtls-rprx-vision
Security: reality
SNI: www.microsoft.com
```

Get UUID:
```bash
main.sh → 11 → 8
# Or: sudo grep '"id"' /etc/vless/config-a.json | head -1
```

## Documentation

- **README.md** - Complete guide
- **VLESS_QUICKREF.md** - This file

---

**Version:** 1.0 | **Updated:** 2026-01-16
