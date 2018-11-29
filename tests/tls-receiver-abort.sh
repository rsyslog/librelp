#!/bin/bash
# added 2018-11-15 by Rainer Gerhards, released under ASL 2.0
# check that receiver abort is handled gracefully
# of messages
. ${srcdir:=$(pwd)}/test-framework.sh
NUMMESSAGES=100000

actual_test() {
	startup_receiver
	./send -t 127.0.0.1 -p $TESTPORT -n$NUMMESSAGES \
		--kill-on-msg 20000 --kill-pid $RECEIVE_PID $OPT_VERBOSE &
	SENDER_PID=$!

	for i in {1..3};  do
		sleep 2
		timeout 10s ${srcdir}/dummyserver.py $TESTPORT
	done

	sleep 2 # make sure client goes into retry

	startup_receiver --append-outfile
	wait $SENDER_PID
	printf 'wait on sender retured %d\n' $?
	stop_receiver

	check_msg_count
}

do_tls_subtests
terminate
