#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

if ! ./have_tlslib openssl; then
	echo 'SKIP: OpenSSL server support is required'
	exit 77
fi

start_server() {
	startup_receiver -l openssl -T -y "$1" -z "$2"
}

actual_test() {
	start_server "${srcdir}/tls-certs/cert.pem" "${srcdir}/tls-certs/key.pem"

	./send -l "$TEST_TLS_LIB" -t 127.0.0.1 -p "$TESTPORT" -m trusted-server \
		-T -a name -x "${srcdir}/tls-certs/ca.pem" -P testbench.rsyslog.com \
		1>>"${OUTFILE}" 2>&1
	stop_receiver
	check_output trusted-server

	start_server "${srcdir}/tls-certs/ossl-server-cert.pem" \
		"${srcdir}/tls-certs/ossl-server-key.pem"

	if ./send -l "$TEST_TLS_LIB" -t 127.0.0.1 -p "$TESTPORT" -m untrusted-server \
		-T -a name -x "${srcdir}/tls-certs/ca.pem" -P testbench.rsyslog.com \
		1>>"${OUTFILE}" 2>&1; then
		printf 'FAIL: untrusted server was accepted without a client certificate\n'
		stop_receiver
		exit 1
	fi
	stop_receiver
	if check_output_only untrusted-server; then
		printf 'FAIL: untrusted server received a message\n'
		exit 1
	fi
}

do_tls_subtests
terminate
