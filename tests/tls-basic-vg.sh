#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
check_command_available valgrind
if [ "$VALGRIND" == "NO" ] ; then
   echo "valgrind tests are not permitted by environment config"
   exit 77
fi
if [ $(uname) = "SunOS" ] ; then
   echo "This test currently does not work on all flavors of Solaris."
   exit 77
fi
if [ $(uname) = "FreeBSD" ] ; then
   echo "This test currently does not work on FreeBSD."
   exit 77
fi

function actual_test() {
	startup_receiver_valgrind -l $TEST_TLS_LIB -T -a "name" -e error.out.log -O $OUTFILE \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P "rsyslog-client"

	echo 'Send Message...'
	libtool --mode=execute $valgrind \
		./send -l $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T \
		-a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P "rsyslog-client" $OPT_VERBOSE

	stop_receiver

	check_output "testmessage"
}

do_tls_subtests
terminate
