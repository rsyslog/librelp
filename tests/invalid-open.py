#!/usr/bin/env python3

import os
import socket
import time


def main():
    port = int(os.environ["TESTPORT"])
    send_invalid_open(port, b"relp_version\n", 12)

    offers = b"commands=" + b",".join([b"syslog"] * 65)
    response = send_invalid_open(port, offers)
    if b"200 OK" in response:
        raise RuntimeError(
            "server accepted an open frame with too many offer values: " + repr(response)
        )


def send_invalid_open(port, offers, length=None):
    if length is None:
        length = len(offers)
    frame = b"1 open " + str(length).encode("ascii") + b" " + offers
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", port))
    sock.sendall(frame)
    try:
        response = sock.recv(1024)
    except socket.timeout:
        response = b""
    time.sleep(0.1)
    sock.close()
    return response


if __name__ == "__main__":
    main()
