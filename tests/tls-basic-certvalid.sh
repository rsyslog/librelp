#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
startup_receiver -T -a "certvalid" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem  -e error.out.log

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "certvalid" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem $OPT_VERBOSE 1>>librelp.out.log 2>&1

stop_receiver
check_output "testmessage"
terminate
