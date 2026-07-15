# wireguard-statistics

## Use

Via an environment variable:

```bash
# Setting the environment variable
export WIREGUARD_STATS_CONFIG=/etc/wireguard/stats-config.yaml

# Running the script
sudo -E ./wireguard-stats

# Or as a single line
sudo WIREGUARD_STATS_CONFIG=/etc/wireguard/stats-config.yaml ./wireguard-stats
```

Via a command-line argument:

```bash
sudo ./wireguard-stats /etc/wireguard/stats-config.yaml
```

Without specifying (default):

```bash
# Looks for config.yaml in the current directory
sudo ./wireguard-stats
```

For a systemd service

# service file /etc/systemd/system/wireguard-stats.service

```ini
[Unit]
Description=WireGuard Statistics Collector
After=network.target mysql.service

[Service]
Type=simple
User=root
Environment=WIREGUARD_STATS_CONFIG=/etc/wireguard/stats-config.yaml
ExecStart=/usr/local/bin/wireguard-stats
Restart=always
RestartSec=10

# Дополнительные настройки безопасности
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=/var/lib/wireguard-stats

[Install]
WantedBy=multi-user.target
```

