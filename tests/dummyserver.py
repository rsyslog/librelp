#!/usr/bin/env python
# a very simple "dummy" server for testing purposes
# written 2018-11-19 by Rainer Gerhards, released under ASL 2.0
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", port))
sock.listen(1)
print "DUMMYSERVER: listening on port", port

conn, addr = sock.accept()
data = conn.recv(1024)
conn.shutdown(socket.SHUT_RDWR)
sock.shutdown(socket.SHUT_RDWR)
conn.close()
sock.close()
