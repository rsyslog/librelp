#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
check_command_available valgrind
if [ "$VALGRIND" == "NO" ] ; then
	echo "valgrind tests are not permitted by environment config"
	exit 77
fi
if ! ./have_tlslib "openssl"; then
	echo "OpenSSL support is not available"
	exit 77
fi

export errorlog="error.$LIBRELP_DYN.log"
export TLSLIB="-l openssl"
export valgrind_log="$TESTDIR/valgrind.log"
export valgrind="$valgrind --leak-check=full --show-leak-kinds=definite --log-file=$valgrind_log"

startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem \
	-y ${srcdir}/tls-certs/ossl-server-cert.pem -z ${srcdir}/tls-certs/ossl-server-key.pem \
	-P "client.testbench.rsyslog.com" -e $TESTDIR/$errorlog

libtool --mode=execute $valgrind ./send $TLSLIB -t 127.0.0.1 -p $TESTPORT \
	-m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem \
	-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
	-P "server.testbench.rsyslog.com" -e $TESTDIR/$errorlog $OPT_VERBOSE
sender_status=$?

stop_receiver
if [ $sender_status -ne 1 ]; then
	echo "unexpected sender exit status $sender_status (expected authentication failure)"
	exit 1
fi
if grep -q "SSL_new" $valgrind_log; then
	echo "failed outbound TLS setup retained an SSL object"
	cat $valgrind_log
	exit 1
fi
check_output "authentication error.*signed certificate in certificate chain" $TESTDIR/$errorlog -z
terminate
