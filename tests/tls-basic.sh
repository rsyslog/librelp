#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

function actual_test() {
	startup_receiver -l $TEST_TLS_LIB -T -a "name" -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P 'testbench.rsyslog.com' -e error.out.log

	./send -l $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P 'testbench.rsyslog.com' $OPT_VERBOSE

	stop_receiver
	check_output "testmessage"
}

do_tls_subtests
terminate
