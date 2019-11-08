#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

function actual_test() {
	startup_receiver --tls-lib $TEST_TLS_LIB -T -a "name" -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P 'testbench.rsyslog.com' \
		--errorfile error.out.log \
		-c "Protocol=ALL,-SSLv2,-SSLv3,-TLSv1,-TLSv1.2"

	echo 'Send Message...'
	./send --tls-lib $TEST_TLS_LIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" \
		-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
		-z ${srcdir}/tls-certs/key.pem -P 'testbench.rsyslog.com' \
		-c "Protocol=-ALL,TLSv1.2" \
		--errorfile error.out.log \
		$OPT_VERBOSE

	stop_receiver
	
	# Test only supported for OpenSSL
	if [ "$TEST_TLS_LIB" == "openssl" ]; then
		check_output --check-only "OpenSSL Version too old" error.out.log
		ret=$?
		if [ $ret == 0 ]; then
			echo "SKIP: OpenSSL Version too old"
			exit 77
		else
			if test -f "error.out.log"; then
				check_output "error opening connection to remote peer" error.out.log
			else
				echo "SKIP: error.out.log was not created"
				exit 77
			fi
		
		fi
	fi
}

do_tls_subtests
terminate

