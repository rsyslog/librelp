#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P '*.rsyslog.com' -e error.out.log

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P '*.rsyslog.com' $OPT_VERBOSE

stop_receiver
check_output "testmessage"
terminate
