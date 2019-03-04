#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
export TLSLIB="--tls-lib openssl"
startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem -y ${srcdir}/tls-certs/ossl-server-cert.pem -z ${srcdir}/tls-certs/ossl-server-key.pem -P 'client.testbench.rsyslog.com' -e $TESTDIR/error.out.log

echo 'Send Message...'
./send $TLSLIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P 'server.testbench.rsyslog.com' --errorfile $TESTDIR/error.out.log $OPT_VERBOSE

stop_receiver
# Perform multiline GREP with -z
check_output "authentication error.*signed certificate in certificate chain" $TESTDIR/error.out.log -z
terminate
