#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
. ${srcdir:=$(pwd)}/test-framework.sh

startup_receiver -1 1 -2 2 -3 3
$PYTHON ${srcdir}/session-limits.py || exit 1
stop_receiver

actual_test() {
	startup_receiver -l $TEST_TLS_LIB -T -a name \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P testbench.rsyslog.com \
		-1 1 -2 2
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
