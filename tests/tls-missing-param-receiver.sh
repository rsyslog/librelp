#!/bin/bash
# This is a self test for the testbench! It does NOT test Relp.
echo 'Start Receiver...'
. ${srcdir:=$(pwd)}/test-framework.sh

function actual_test() {
	# NOT USING startup_receiver!
	./receive -l $TEST_TLS_LIB -p $TESTPORT -T -a "name" \
		-y ${srcdir}/tls-certs/cert.pem -P "rsyslog" \
		2> $OUTFILE

	check_output "receive:.*parameter missing; certificates and permittedPeer required"
}

do_tls_subtests
terminate
