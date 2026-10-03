#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
export errorlog="error.$LIBRELP_DYN.log"
export TLSLIB="-l openssl"

startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem \
	-y ${srcdir}/tls-certs/ossl-server-cert.pem \
	-z ${srcdir}/tls-certs/ossl-server-key.pem \
	-P 'client.testbench.rsyslog.com' -e $TESTDIR/$errorlog

./send $TLSLIB -t 127.0.0.1 -p $TESTPORT -m "untrusted-server" \
	-T -a "certvalid" -x ${srcdir}/tls-certs/ca.pem \
	-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
	-e $TESTDIR/$errorlog $OPT_VERBOSE > $TESTDIR/sender.log 2>&1

stop_receiver
check_output "send: authentication error.*self[- ]signed certificate in certificate chain" \
	$TESTDIR/sender.log -z
terminate
