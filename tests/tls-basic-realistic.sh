#!/bin/bash
# added 2018-11-15 by Rainer Gerhards, released under ASL 2.0
# a more relastic test which actually sends a bit larger number
# of messages
. ${srcdir:=$(pwd)}/test-framework.sh
NUMMESSAGES=50000

function actual_test() {
	startup_receiver --tls-lib $TEST_TLS_LIB -T -a "name" -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P 'testbench.rsyslog.com' -e error.out.log
	./send --tls-lib $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -n$NUMMESSAGES -T -a "name" \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P 'testbench.rsyslog.com' $OPT_VERBOSE
	stop_receiver
	check_msg_count
	printf 'END SUBTEST lib %s SUCCESS\n' $TEST_TLS_LIB
}

do_tls_subtests
terminate
