#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
# export OPT_VERBOSE=-v # uncomment for debugging 
export errorlog="error.$LIBRELP_DYN.log"

if ! ./have_tlslib "gnutls"; then
	echo 'Skipping test, missing supported for gnutls in this build'
	exit;
fi
if ! ./have_tlslib "openssl"; then
	echo 'Skipping test, missing supported for openssl in this build'
	exit;
fi

startup_receiver --tls-lib openssl -T -a "certvalid" -e "${TESTDIR}/${errorlog}" \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem

echo 'Send Message...'
./send --tls-lib gnutls -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "certvalid" -e "${TESTDIR}/${errorlog}" \
	-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem $OPT_VERBOSE 1>>${OUTFILE} 2>&1

stop_receiver

if test -f $TESTDIR/$errorlog; then
	# Check for "handshake failed"
	check_output --check-only "handshake failed" $TESTDIR/$errorlog
	ret=$?
	if [ $ret == 0 ]; then
		echo "SKIP: Handshake failed, TLS Version most likely to old!"
		exit 77
	else 
		echo $TESTDIR/$errorlog
		cat $TESTDIR/$errorlog
	fi
fi

check_output "testmessage"

terminate
