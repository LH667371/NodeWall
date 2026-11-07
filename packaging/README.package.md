# NodeWall Package Guide

This package is for deployment only.

## Included

- `bin/nodewall`: unified runtime and operations binary

## Install

Run the host preflight first:

```sh
sudo ./bin/nodewall preflight
```

Installation runs the same checks and stops before writing files when a hard
failure is found.

```sh
sudo ./bin/nodewall install --password 'change-me'
```

This installs NodeWall into:

- binaries: `/opt/nodewall/bin`
- config: `/etc/nodewall`
- services: `nodewall-agent.service`, `nodewall-server.service`

By default:

- web server listens on `0.0.0.0:8080` so other LAN devices can access it
- agent listens on `127.0.0.1:9080`
- drop logs are written to `/var/lib/nodewall/logs`
- drop log state is stored in `/etc/nodewall/drop-log-state.json`
- retention defaults to `7` days with a `30s` flush interval

## Legacy Kernel Compatibility

The installer uses `--dataplane auto` by default. Kernels older than `4.18`,
including CentOS 7 `3.10`, use the isolated iptables compatibility backend.
It protects both host-originated egress traffic and bridge-forwarded egress
traffic without altering ZStack-managed chains. This backend must not be used
on Kubernetes nodes.

The cluster baseline always preserves manager TCP port `8082`. Enrollment and
server restart reconcile the interconnect addresses and control port on existing
node policies. New nodes stay observe-only until the UI enables protection; the
UI can also run a `1` to `120` second trial that automatically restores the
previous state unless explicitly confirmed.

## Change Password

```sh
sudo /opt/nodewall/bin/nodewall set-password --file /etc/nodewall/auth.json --password 'new-password'
```

## Update

Extract the new package and run this from the new directory:

```sh
sudo ./bin/nodewall update
```

The update keeps your existing config, password, and ports. It refreshes:

- `/opt/nodewall/bin/nodewall`
- `/opt/nodewall/web`
- `/opt/nodewall/bpf/gen/xdpacl_bpfel.o`
- systemd unit files

By default it performs an in-place restart of running services. To stage files
without restarting immediately:

```sh
sudo ./bin/nodewall update --restart-services=false
```

## Port Conflict

If the preferred port is busy, the installer automatically picks the next free
port. For example, if `8080` is occupied it will try `8081`, `8082`, and so on.

You can still force explicit ports:

```sh
sudo ./bin/nodewall install \
  --server-addr 0.0.0.0:18080 \
  --agent-addr 127.0.0.1:19080 \
  --agent-url http://127.0.0.1:19080 \
  --password 'change-me'
```

The installer checks port availability before writing `/etc/nodewall/nodewall.env`.

If you need to change ports later, edit `/etc/nodewall/nodewall.env` and restart:

```sh
sudo systemctl restart nodewall-agent.service
sudo systemctl restart nodewall-server.service
```

## Service Checks

```sh
systemctl status nodewall-agent.service
systemctl status nodewall-server.service
```

## Management Page

After installation, open the NodeWall Web UI and use the `Management` section to:

- change the login password
- enable or disable persisted drop logs
- adjust retention days
- adjust the flush interval
- view the active log directory
- clear persisted drop log history

If you prefer editing the environment file directly:

```sh
sudo vi /etc/nodewall/nodewall.env
```

Common logging variables:

- `NODEWALL_LOG_DIR`
- `NODEWALL_DROP_LOG_ENABLED`
- `NODEWALL_DROP_LOG_RETENTION_DAYS`
- `NODEWALL_DROP_LOG_FLUSH_INTERVAL`
- `NODEWALL_DROP_LOG_STATE`

Common login protection variable:

- `NODEWALL_AUTH_SETTINGS_FILE`
- `NODEWALL_SSH_AUTH_LOG` (empty uses `auth.log`, `secure`, or `journalctl` automatically)

The `Management` page also exposes a `Brute-force protection` panel where you can adjust:

- max failures before lock
- the failure window
- lock duration
- the current count of active locks

Restart services after edits:

```sh
sudo systemctl restart nodewall-agent.service
sudo systemctl restart nodewall-server.service
```

To inspect log files directly:

```sh
ls -lah /var/lib/nodewall/logs
tail -f /var/lib/nodewall/logs/drop-$(date +%F).jsonl
```

## Cleanup

```sh
sudo ./bin/nodewall cleanup
```
