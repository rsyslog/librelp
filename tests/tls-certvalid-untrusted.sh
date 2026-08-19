#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
function actual_test() {
	local errorlog="${TESTDIR}/error.out.log"
	startup_receiver -l $TEST_TLS_LIB -T -a "certvalid" \
		-x ${srcdir}/tls-certs/ossl-ca.pem \
		-y ${srcdir}/tls-certs/ossl-server-cert.pem \
		-z ${srcdir}/tls-certs/ossl-server-key.pem \
		-e "$errorlog"

	echo 'Send Message with expired client certificate...'
	if ./send -l $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "certvalid" \
		-x ${srcdir}/tls-certs/ossl-ca.pem \
		-y ${srcdir}/tls-certs/ossl-clientbrok-cert.pem \
		-z ${srcdir}/tls-certs/ossl-clientbrok-key.pem \
		$OPT_VERBOSE 1>>${OUTFILE} 2>&1; then
		printf 'FAIL: send succeeded with an invalid certificate in certvalid mode\n'
		stop_receiver
		exit 1
	fi

	stop_receiver
	check_output "certificate validation failed" "$errorlog"
}

do_tls_subtests
terminate
