#!/usr/bin/env python3
"""Synthetic F-076 lab client. Never prints or saves credentials."""
import json
import os
import re
import sys

import pymysql


def emit(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def db(password, port):
    return pymysql.connect(host="127.0.0.1", port=port, user="root",
                           password=password, connect_timeout=5, autocommit=True)


def read_passwords(path):
    with open(path, "r", encoding="utf-8") as stream:
        content = stream.read()
    return re.findall(r"\$cfg\['Servers'\]\[\$i\]\['password'\] = '([^']*)';", content)


def main():
    mode = sys.argv[1]
    path = sys.argv[2]
    port = int(sys.argv[3])
    if mode == "owner-init":
        with db(os.environ["Parameters__f076one"], port) as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE DATABASE IF NOT EXISTS f076_owned")
                cur.execute("CREATE TABLE IF NOT EXISTS f076_owned.marker (id INT PRIMARY KEY, status VARCHAR(32))")
                cur.execute("REPLACE INTO f076_owned.marker VALUES (1, 'owner')")
        emit(mode=mode, owner_initialized=True)
        return 0
    if mode == "owner-check":
        with db(os.environ["Parameters__f076one"], port) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM f076_owned.marker WHERE id=1")
                value = cur.fetchone()[0]
        emit(mode=mode, status=value)
        return 0 if value == "other" else 5
    if mode == "deny":
        try:
            with db("deliberately-wrong-f076", port):
                pass
        except pymysql.err.OperationalError as exc:
            emit(mode=mode, denied=exc.args[0] == 1045, mysql_error=exc.args[0])
            return 0 if exc.args[0] == 1045 else 6
        emit(mode=mode, denied=False)
        return 7
    if mode == "read-permission":
        try:
            read_passwords(path)
        except PermissionError:
            emit(mode=mode, denied_by_filesystem=True)
            return 0
        emit(mode=mode, denied_by_filesystem=False)
        return 8
    if mode == "read":
        try:
            passwords = read_passwords(path)
        except OSError as exc:
            emit(mode=mode, read_error=type(exc).__name__)
            return 9
        if len(passwords) != 2:
            emit(mode=mode, password_count=len(passwords))
            return 10
        with db(passwords[0], port) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE f076_owned.marker SET status='other' WHERE id=1")
                affected = cur.rowcount
                cur.execute("SELECT CURRENT_USER()")
                principal = cur.fetchone()[0]
        emit(mode=mode, file_read=True, password_count=len(passwords),
             mysql_principal=principal, rows_changed=affected)
        return 0 if affected == 1 else 11
    emit(error="unknown mode")
    return 12


if __name__ == "__main__":
    sys.exit(main())
