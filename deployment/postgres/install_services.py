"""Install root-owned monitoring, backup and database tunnel systemd units."""
import argparse
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['center', 'probe'], required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    scripts = root / 'deployment/postgres'
    python = root / 'systemwire2/venv/bin/python' if args.role == 'center' else Path('/opt/honeypot/db-tools/bin/python')
    state = Path('/var/lib/honeypot')
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    units = Path('/etc/systemd/system')

    def scheduled(name, description, command, schedule):
        (units / (name + '.service')).write_text(
            '[Unit]\nDescription=' + description + '\nAfter=network-online.target\n'
            '[Service]\nType=oneshot\nUMask=0077\nNice=10\nEnvironmentFile=/etc/honeypot/systemwire.env\n'
            'ExecStart=' + command + '\n')
        (units / (name + '.timer')).write_text(
            '[Unit]\nDescription=' + description + '\n[Timer]\n' + schedule +
            '\n[Install]\nWantedBy=timers.target\n')

    scheduled('honeypot-db-capacity', 'Honeypot storage capacity inspection',
              f'{python} {scripts}/storage.py capacity --output {state}/capacity.json',
              'OnBootSec=5min\nOnUnitActiveSec=1h')
    enabled = ['honeypot-db-capacity.timer']
    if args.role == 'center':
        (units / 'honeypot-db-tunnel.service').write_text(
            '[Unit]\nDescription=Encrypted connection to honeypot PostgreSQL\n'
            'After=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n'
            '[Service]\nType=simple\nExecStart=/usr/bin/ssh -NT -i /etc/honeypot/database_ed25519 '
            '-o BatchMode=yes -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes '
            '-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 '
            '-L 127.0.0.1:15433:127.0.0.1:5432 hptunnel@43.163.94.52\n'
            'Restart=always\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n')
        for service, env in [('alert_server', 'alert-server.env'), ('systemwire2', 'systemwire.env')]:
            directory = units / (service + '.service.d')
            directory.mkdir(exist_ok=True)
            (directory / 'postgres.conf').write_text(
                '[Unit]\nAfter=honeypot-db-tunnel.service\nWants=honeypot-db-tunnel.service\n'
                '[Service]\nEnvironmentFile=/etc/honeypot/' + env + '\nRestart=always\nRestartSec=5\n')
        enabled.append('honeypot-db-tunnel.service')
        scheduled('honeypot-backup-inventory', 'Verify and rotate received honeypot backups',
                  f'{python} {scripts}/backup_inventory.py', 'OnBootSec=10min\nOnUnitActiveSec=6h')
        enabled.append('honeypot-backup-inventory.timer')
    else:
        scheduled('honeypot-db-backup', 'Honeypot verified database backup',
                  f'{python} {scripts}/backup.py',
                  'OnCalendar=*-*-* 03:15:00\nRandomizedDelaySec=10min\nPersistent=true')
        enabled.append('honeypot-db-backup.timer')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', *enabled], check=True)


if __name__ == '__main__':
    main()
