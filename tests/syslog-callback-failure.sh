#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

for receiver_mode in -q -Q; do
	startup_receiver "$receiver_mode" -C "$TESTDIR/sessions.log"
	$PYTHON - <<'PYTEST' || exit 1
import os
import socket

sock = socket.create_connection(("127.0.0.1", int(os.environ["TESTPORT"])), 3)
sock.settimeout(3)
offers = b"relp_version=0\ncommands=syslog\n"
sock.sendall(b"1 open " + str(len(offers)).encode() + b" " + offers + b"\n")
response = b""
while b"200 OK" not in response:
    chunk = sock.recv(4096)
    if not chunk:
        raise AssertionError("connection closed before open response")
    response += chunk
sock.sendall(b"2 syslog 11 testmessage\n")
response = b""
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    response += chunk
if b"200 OK" in response:
    raise AssertionError("server acknowledged failed delivery: " + repr(response))
sock.close()
PYTEST
	./msleep 200
	stop_receiver
	if ! grep -q 'session closed reason=10017' "$TESTDIR/sessions.log"; then
		echo "failed callback did not close the session for receiver mode $receiver_mode"
		exit 1
	fi
	if [ -s "$OUTFILE" ]; then
		echo "failed syslog callback delivered a message"
		exit 1
	fi
	rm -f "$TESTDIR/sessions.log"
done

terminate
