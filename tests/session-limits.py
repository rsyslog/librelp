#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise server admission and both session deadlines with real TCP sockets."""

import errno
import os
import socket
import sys
import time


PORT = int(os.environ["TESTPORT"])
ADDR = ("127.0.0.1", PORT)
now = getattr(time, "monotonic", time.time)


def connect():
    sock = socket.create_connection(ADDR, timeout=2)
    sock.settimeout(0.2)
    return sock


def wait_closed(sock, seconds=4):
    deadline = now() + seconds
    while now() < deadline:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        if not data:
            return
    raise AssertionError("session did not close before its deadline")


def open_session():
    sock = connect()
    offers = b"relp_version=0\ncommands=syslog\n"
    sock.sendall(b"1 open " + str(len(offers)).encode() + b" " + offers + b"\n")
    deadline = now() + 2
    response = b""
    while b"200 OK" not in response and now() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise AssertionError("server closed a valid RELP open")
        response += chunk
    if b"200 OK" not in response:
        raise AssertionError("server did not answer valid RELP open: " + repr(response))
    return sock


def main():
    stalled = connect()
    stalled.sendall(b"1")
    time.sleep(0.2)
    rejected = connect()
    wait_closed(rejected, 2)
    rejected.close()

    # Keep the frame incomplete while bytes arrive more often than the timeout.
    # A sliding timeout would keep this socket open past the absolute deadline.
    closed = False
    for _ in range(8):
        time.sleep(0.4)
        try:
            stalled.sendall(b"1")
            if stalled.recv(1) == b"":
                closed = True
                break
        except socket.timeout:
            pass
        except socket.error as exc:
            if exc.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
                raise
            closed = True
            break
    if not closed:
        raise AssertionError("partial open stayed alive under continuous trickle")
    stalled.close()

    established = open_session()
    # The established session is still subject to the capacity limit.
    rejected = connect()
    wait_closed(rejected, 2)
    rejected.close()
    time.sleep(1.4)
    established.sendall(b"2 syslog 5 hello\n")
    response = b""
    deadline = now() + 2
    while b"200 OK" not in response and now() < deadline:
        try:
            chunk = established.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        response += chunk
    if b"200 OK" not in response:
        raise AssertionError("established session did not accept syslog: " + repr(response))
    time.sleep(1.5)
    try:
        if established.recv(1) == b"":
            raise AssertionError("active session expired before its idle deadline")
    except socket.timeout:
        pass
    wait_closed(established)
    established.close()

    # Bytes of an unfinished frame are not activity: a peer that trickles
    # single octets of a frame more often than the idle timeout must still be
    # closed once the idle deadline passes after its last complete frame.
    trickler = open_session()
    closed = False
    for octet in b"2 syslog 100 ":
        time.sleep(0.5)
        try:
            trickler.sendall(bytes([octet]))
            if trickler.recv(1) == b"":
                closed = True
                break
        except socket.timeout:
            pass
        except socket.error as exc:
            if exc.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
                raise
            closed = True
            break
    if not closed:
        raise AssertionError("established session stayed alive under byte trickle")
    trickler.close()

    replacement = open_session()
    replacement.close()


def stalled_tls_handshake():
    stalled = connect()
    time.sleep(0.2)
    rejected = connect()
    wait_closed(rejected, 2)
    rejected.close()
    wait_closed(stalled)
    stalled.close()


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--tls-stall":
        stalled_tls_handshake()
    else:
        main()
