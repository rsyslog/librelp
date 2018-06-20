#!/bin/bash
. ${srcdir}/test-framework.sh
# NOT USING startup_receiver here!
./receive -p $TESTPORT -T -a "anon" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog" $OPT_VERBOSE $* 1>>librelp.out.log 2>&1
check_output "relpSrvSetAuthMode(pRelpSrv, authMode)"

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "anon" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog" $OPT_VERBOSE 1>>client.err.log 2>&1
check_output "relpCltSetAuthMode(pRelpClt, authMode)" client.err.log

terminate
