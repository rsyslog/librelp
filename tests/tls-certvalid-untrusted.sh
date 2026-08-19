#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
function actual_test() {
	startup_receiver -l $TEST_TLS_LIB -T -a "certvalid" \
		-x ${srcdir}/tls-certs/ossl-ca.pem \
		-y ${srcdir}/tls-certs/ossl-server-cert.pem \
		-z ${srcdir}/tls-certs/ossl-server-key.pem \
		-e error.out.log

	echo 'Send Message with expired client certificate...'
	./send -l $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "certvalid" \
		-x ${srcdir}/tls-certs/ossl-ca.pem \
		-y ${srcdir}/tls-certs/ossl-clientbrok-cert.pem \
		-z ${srcdir}/tls-certs/ossl-clientbrok-key.pem \
		$OPT_VERBOSE 1>>${OUTFILE} 2>&1
	if [ $? -eq 0 ]; then
		printf 'FAIL: send succeeded with an invalid certificate in certvalid mode\n'
		stop_receiver
		exit 1
	fi

	stop_receiver
	check_output "certificate validation failed" error.out.log
}

do_tls_subtests
terminate
