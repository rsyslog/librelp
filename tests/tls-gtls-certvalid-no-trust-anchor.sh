#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

if ! ./have_tlslib "gnutls"; then
	echo 'Skipping test, missing support for gnutls in this build'
	exit 77
fi

errorlog="${TESTDIR}/error.log"
startup_receiver -l gnutls -T -a "certvalid" \
	-y ${srcdir}/tls-certs/ossl-server-certchain.pem \
	-z ${srcdir}/tls-certs/ossl-server-key.pem \
	-e $errorlog

echo 'Send certificate to server without configured trust anchors...'
./send -l gnutls -t 127.0.0.1 -p $TESTPORT -m "testmessage" \
	-T -a "certvalid" \
	-x ${srcdir}/tls-certs/ossl-ca.pem \
	-y ${srcdir}/tls-certs/ossl-client-certchain.pem \
	-z ${srcdir}/tls-certs/ossl-client-key.pem \
	-e $errorlog $OPT_VERBOSE 1>>${OUTFILE} 2>&1

stop_receiver
check_output "authentication error.*certificate validation failed" $errorlog
terminate
