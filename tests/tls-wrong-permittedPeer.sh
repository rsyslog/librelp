#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
export TLSLIB="--tls-lib openssl"
startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "wrong name" -e error.out.log

echo 'Send Message...'
./send $TLSLIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "wrong name" --errorfile error.out.log $OPT_VERBOSE

stop_receiver
check_output "authentication error.*no permited name found.*testbench.rsyslog.com" error.out.log
terminate
