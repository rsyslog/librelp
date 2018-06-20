#!/bin/bash
if [ `uname` = "SunOS" ] ; then
   echo "This test currently does not work on all flavors of Solaris."
   exit 77
fi
if [ `uname` = "FreeBSD" ] ; then
   echo "This test currently does not work on FreeBSD."
   exit 77
fi

. ${srcdir}/test-framework.sh

echo 'Start Receiver...'
startup_receiver_valgrind -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog-client"

echo 'Send Message...'
$valgrind ./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog-client" $OPT_VERBOSE 1>>librelp.out.log 2>&1

stop_receiver

check_output "testmessage"
terminate
