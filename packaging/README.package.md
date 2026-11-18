# NodeWall Package Guide

This package is for deployment only.

Update only the repository `VERSION` file to change the product release number.
The console, node heartbeats, and default package names use that version.
Release automation can set
`NODEWALL_PACKAGE_REVISION` and `NODEWALL_PACKAGE_LABEL` when a traceable or
reproducible build identifier is required.

## Included

- `bin/nodewall`: unified runtime and operations binary
- `README.md`, `README.zh-CN.md`: operations guides

Archives with `_offline_` in the filename also include:

- `clamav/engines/`: private ClamAV runtimes for `amd64` and `arm64`
- `clamav/database/`: signature-verified `main`, `daily`, and `bytecode` databases
- `clamav/NOTICE.md`: third-party component and source information
- `clamav/source/`: corresponding ClamAV source and Alpine build patches

Archives with `_update_` in the filename omit `clamav/` and preserve any
engine and databases already installed on the target. Provision ClamAV with
an offline archive, or synchronize it from any enrolled node with those assets.
Nodes check at startup and every two minutes, including an original manager
without assets; enrollment does not wait for the background transfer to finish.

The offline archive supports installation on Ubuntu and CentOS without
replacing host libraries or an existing ClamAV installation. The private
daemon runs with the NodeWall agent and keeps its data under
`/var/lib/nodewall/clamav`. Allow approximately 3–4 GiB of available memory
for loading the full database and leave adequate disk space. The active
manager uses FreshClam for hourly upstream updates; enrolled nodes fetch newer
engines and individual databases from peers over authenticated, pinned HTTPS.
Offline bundles can be served before the source daemon initializes. Recipients
verify digests, CVD signatures, and full database loading before activation.
Engine upgrades restart the private clamd, without downgrading local versions.
The previous working version is retained if an
update fails. An update archive or binary-only artifact does not include the
offline engine; a node without it must obtain it from an enrolled peer or an offline
archive. Signature detection does not guarantee detection of unknown malware.

FreshClam uses the bundled public CA certificates. To trust an enterprise
proxy, set `NODEWALL_CLAMAV_CA_FILE` to a PEM bundle that includes its CA.

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

systemd is the default service manager. To install without systemd, explicitly
select the SysV manager:

```sh
sudo ./bin/nodewall install --service-manager=sysv --password 'change-me'
```

This writes `/etc/init.d/nodewall-agent` and `/etc/init.d/nodewall-server`,
registers them with `chkconfig` or `update-rc.d`, and adds
`/etc/cron.d/nodewall` as an `@reboot` fallback. The scripts restart either
process after a non-zero exit and write logs to `/var/log/nodewall/agent.log`
and `/var/log/nodewall/server.log`. With `--enable-services=false`, no boot
entry is installed.

The enrollment script uses that disabled phase only while it copies the standby
snapshot. It then enables both systemd units (with a unit-link fallback when the
systemd bus is temporarily unavailable) before starting the local processes.

By default:

- web server listens on `0.0.0.0:8086` so other LAN devices can access it
- A new secure all-in-one installation listens on `0.0.0.0:9080` and advertises
  its usable IPv4 address when one is detected. Explicit bind settings, disabled
  TLS, and installations without a usable address retain their configured
  behavior. An explicit loopback bind prevents other managers from reaching the agent.
- enrolled cluster members also run the management web server and keep a
  synchronized manager snapshot, so another member can serve the console when
  the active manager is offline; all management services use the 8086+ port
  range. Upgrades and re-enrollment migrate legacy values from 8080 through
  8085 before reporting the selected address in node heartbeats
- drop logs are written to `/var/lib/nodewall/logs`
- drop log state is stored in `/etc/nodewall/drop-log-state.json`
- retention defaults to `7` days with a `30s` flush interval

## Legacy Kernel Compatibility

The installer uses `--dataplane auto` by default and always selects XDP + TC eBPF.
It never silently switches to iptables on an older kernel; preflight fails below
`4.18` so the operator can upgrade the kernel or explicitly choose the legacy
backend.
The explicit legacy backend filters only host traffic in private
`filter/INPUT` and `filter/OUTPUT` chains. Conntrack preserves established
DNS/HTTPS/SSH replies after explicit blocks and port denies have been checked.
Guest forwarding and ZStack raw/NFLOG rules remain untouched. Upgrades remove
only obsolete NodeWall raw/mangle hooks; no `/etc/iptables` files are written.
This backend must not be used on Kubernetes nodes.

The cluster baseline always preserves manager TCP port `8082`. Enrollment and
server restart reconcile the interconnect addresses and control port on existing
node policies. New nodes stay observe-only until the UI enables protection; the
UI can also run a `1` to `120` second trial that automatically restores the
previous state unless explicitly confirmed.

## Change Password

```sh
sudo /opt/nodewall/bin/nodewall set-password --file /etc/nodewall/auth.json --password 'new-password'
```

## State and Credential Protection

Production installs generate `/etc/nodewall/cluster.key` and use AES-GCM to
protect manager state, enrolled-node credentials, login accounts, and
authentication settings. Each file keeps three rotated copies (`.bak.1` through
`.bak.3`); startup verifies the authentication tag and restores a valid backup
when the primary copy is damaged.

Include `cluster.key` and the configuration directory in controlled backups. A
root-level attacker can still read or remove a local key, so higher-assurance
deployments should replicate the key and snapshots to an independent standby
manager or external key service.

## Update

Extract the new package and run this from the new directory:

```sh
sudo ./bin/nodewall update
```

If the manager has already moved from the legacy `8080` port to `8086+`,
pass the current manager URL once while updating an older enrolled node:

```sh
sudo ./bin/nodewall update --manager-url https://MANAGER_HOST:8086
```

The URL is saved in the node environment. Future heartbeat and update
requests then use the current manager port.

The update keeps your existing config, password, and ports. It refreshes:

- `/opt/nodewall/bin/nodewall`
- `/opt/nodewall/web`
- `/opt/nodewall/bpf/gen/xdpacl_bpfel.o`
- systemd unit files

Web assets are written to the directory configured by `NODEWALL_WEB_DIR`. Legacy installations that still point at an older Web directory are refreshed in place so the restarted service loads the new console.

After the active manager is updated, enrolled agents compare their reported
package version through the heartbeat and roll forward automatically. The
cluster page shows the manager version and each node's reported version. The
updater compares both the installed package marker and the running process
build, so a CentOS host with an unavailable systemd bus cannot silently keep an
old Agent/Web process after replacing files; direct processes and legacy
`nodewall.tmp.*` executables are stopped before the new services start.

By default it performs an in-place restart of running services. To stage files
without restarting immediately:

```sh
sudo ./bin/nodewall update --restart-services=false
```

## Port Conflict

All NodeWall management services start in the 8086+ port range. If the
configured port is busy, installation continues with the next free port;
upgrades migrate legacy server values from `8080` through `8085`.

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

Cleanup stops services and direct processes, restores NodeWall-managed SSH/SFTP
configuration and the root console key, then removes runtime files. If SSH
validation or reload fails, it exits without deleting the recovery files, so a
local-console retry cannot leave a `ForceCommand` pointing at a missing
`/opt/nodewall/bin/nodewall`.
