#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
function actual_test() {
	startup_receiver --tls-lib $TEST_TLS_LIB -T -a "certvalid" -x ${srcdir}/tls-certs/ossl-server-certchain.pem -y ${srcdir}/tls-certs/ossl-server-certchain.pem -z ${srcdir}/tls-certs/ossl-server-key.pem  -e error.out.log

	echo 'Send Message...'
	./send --tls-lib $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "certvalid" -x ${srcdir}/tls-certs/ossl-client-certchain.pem -y ${srcdir}/tls-certs/ossl-client-certchain.pem -z ${srcdir}/tls-certs/ossl-client-key.pem $OPT_VERBOSE 1>>${OUTFILE} 2>&1

	stop_receiver
	check_output "testmessage"
}

do_tls_subtests
terminate
