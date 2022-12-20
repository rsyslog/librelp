#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
export errorlog="error.$LIBRELP_DYN.log"
export TLSLIB="-l openssl"
# export OPT_VERBOSE=-v # uncomment for debugging 

function actual_test() {
	# Test only supported for OpenSSL
	if [ "$TEST_TLS_LIB" == "openssl" ]; then
		startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ca.pem \
			-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
			-P 'testbench.rsyslog.com' \
			-e  $TESTDIR/$errorlog \
			-c "Protocol=ALL,-SSLv2,-SSLv3,-TLSv1,-TLSv1.1;CipherString=ECDHE-RSA-AES256-GCM-SHA384;MinProtocol=TLSv1.2;MaxProtocol=TLSv1.2;Ciphersuites=TLS_AES_256_GCM_SHA384"

		echo 'Send Message...'
		./send $TLSLIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" \
			-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
			-z ${srcdir}/tls-certs/key.pem -P 'testbench.rsyslog.com' \
			-c "CipherString=ECDHE-RSA-AES128-GCM-SHA256;Ciphersuites=TLS_AES_128_GCM_SHA256" \
			-e $TESTDIR/$errorlog \
			$OPT_VERBOSE

		stop_receiver

		if test -f $TESTDIR/$errorlog; then
			check_output --check-only "OpenSSL Version too old" $TESTDIR/$errorlog
			ret=$?
			if [ $ret == 0 ]; then
				echo "SKIP: OpenSSL Version too old"
				exit 77
			else
				# Try "handshake failed" first
				check_output --check-only "handshake fail" $TESTDIR/$errorlog
				ret=$?
				if [ $ret != 0 ]; then
					check_output "wrong version number" $TESTDIR/$errorlog
				fi
			fi
		else
			echo "SKIP: $TESTDIR/$errorlog was not created"
			exit 77
		fi
	else
		echo "SKIP: For $TEST_TLS_LIB"
	fi
}

do_tls_subtests
terminate
