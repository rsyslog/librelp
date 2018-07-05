#!/bin/bash
. ${srcdir}/test-framework.sh
startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem -y ${srcdir}/tls-certs/ossl-server-cert.pem -z ${srcdir}/tls-certs/ossl-server-key.pem -P 'client.testbench.rsyslog.com'

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P 'server.testbench.rsyslog.com' $OPT_VERBOSE 1>>librelp.out.log 2>&1

stop_receiver
check_output "librelp\: auth error\: authdata\:.*, ecode 10036"
terminate
