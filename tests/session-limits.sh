#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

startup_receiver --max-sessions=1 --open-timeout=2 --idle-timeout=3
$PYTHON ${srcdir}/session-limits.py || exit 1
stop_receiver

actual_test() {
	startup_receiver -l $TEST_TLS_LIB -T -a name \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P testbench.rsyslog.com \
		--max-sessions=1 --open-timeout=2
	$PYTHON ${srcdir}/session-limits.py --tls-stall || exit 1
	./send -l $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m recovered \
		-T -a name -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P testbench.rsyslog.com || exit 1
	stop_receiver
	check_output recovered
}
do_tls_subtests
terminate
