#!/usr/bin/env python3

import os
import socket
import time


def main() -> None:
    port = int(os.environ["TESTPORT"])
    frame = b"1 open 12 relp_version\n"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", port))
    sock.sendall(frame)
    try:
        sock.recv(1024)
    except socket.timeout:
        pass
    time.sleep(0.1)
    sock.close()


if __name__ == "__main__":
    main()
