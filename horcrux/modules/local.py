from __future__ import annotations


def enumerate_linux(ws, runner):
    checks = {
        "identity": ["sh", "-c", "id; whoami; hostname"],
        "os": ["sh", "-c", "uname -a; cat /etc/os-release 2>/dev/null"],
        "sudo": ["sudo", "-n", "-l"],
        "suid": ["sh", "-c", "find / -type f -perm -4000 2>/dev/null | sort"],
        "sgid": ["sh", "-c", "find / -type f -perm -2000 2>/dev/null | sort"],
        "caps": ["sh", "-c", "getcap -r / 2>/dev/null"],
        "cron": ["sh", "-c", "cat /etc/crontab 2>/dev/null; find /etc/cron.d -maxdepth 1 -type f -print 2>/dev/null"],
        "systemd": ["sh", "-c", "systemctl list-unit-files --type=service --no-pager 2>/dev/null"],
        "processes": ["sh", "-c", "ps auxww"],
        "network": ["sh", "-c", "ss -lntup 2>/dev/null; ip addr 2>/dev/null"],
        "mounts": ["sh", "-c", "mount; df -h"],
        "docker": ["sh", "-c", "id; docker ps 2>/dev/null; ls -l /var/run/docker.sock 2>/dev/null"],
        "environment": ["sh", "-c", "env"],
    }

    for name, args in checks.items():
        runner.run(args, f"local-{name}", timeout=180)
