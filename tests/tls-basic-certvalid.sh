#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
export errorlog="error.$LIBRELP_DYN.log"

function actual_test() {
	startup_receiver --tls-lib $TEST_TLS_LIB -T -a "certvalid" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem  --errorfile "${TESTDIR}/${errorlog}"

	echo 'Send Message...'
	./send --tls-lib $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "certvalid" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem $OPT_VERBOSE 1>>${OUTFILE} 2>&1

	stop_receiver
	check_output "testmessage"
}

do_tls_subtests
terminate
