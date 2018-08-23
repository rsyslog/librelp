#!/bin/bash
# ***
# *** TEST currently UNSTABLE because SSL Server sometimes discard connection before certificate can even be checked for length!
# ***
. ${srcdir}/test-framework.sh
startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem -y ${srcdir}/tls-certs/ossl-server-cert.pem -z ${srcdir}/tls-certs/ossl-server-key.pem -P 'clientbrok.testbench.rsyslog.com' -e error.out.log

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem -y ${srcdir}/tls-certs/ossl-clientbrok-cert.pem -z ${srcdir}/tls-certs/ossl-clientbrok-key.pem -P 'server.testbench.rsyslog.com' -e error.out.log $OPT_VERBOSE 1>>librelp.out.log 2>&1

stop_receiver
check_output "certificate validation failed, names inside certifcate are way to long" error.out.log
terminate
