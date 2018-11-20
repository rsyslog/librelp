#!/usr/bin/env python

import socket
import os

port = int(os.environ['TESTPORT'])
print "dummyclient info: opening and closing port " + str(port) + " without sending data"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", port))
s.close()
