#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

for receiver_mode in -q -Q; do
	startup_receiver "$receiver_mode" -C "$TESTDIR/sessions.log"
	./send -t 127.0.0.1 -p "$TESTPORT" -m testmessage \
		> "$TESTDIR/sender-${receiver_mode#-}.log" 2>&1
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
