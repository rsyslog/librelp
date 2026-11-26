#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

if ! ./have_tlslib gnutls; then
	exit 77
fi

function actual_test() {
	local fingerprint='SHA256:1E:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6'
	startup_receiver -l gnutls -T -a "fingerprint" \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P "$fingerprint" -e error.out.log
	./send -l gnutls -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T \
		-a "fingerprint" -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P "$fingerprint" $OPT_VERBOSE 1>>${OUTFILE} 2>&1
	stop_receiver
	check_output "testmessage"
}

actual_test
terminate
