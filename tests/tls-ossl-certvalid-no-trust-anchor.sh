#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

if ! ./have_tlslib "openssl"; then
	echo 'Skipping test, missing support for openssl in this build'
	exit 77
fi

# Keep the default certificate directory empty, but point SSL_CERT_FILE at the
# fixture CA. Without an explicit -x, only an implementation that incorrectly
# loads ownCertFile or OpenSSL default paths can trust these peer certificates.
mkdir -p "${TESTDIR}/empty-ca-dir"
export SSL_CERT_DIR="${TESTDIR}/empty-ca-dir"
export SSL_CERT_FILE="${srcdir}/tls-certs/ossl-ca.pem"

errorlog="${TESTDIR}/error.log"
startup_receiver -l openssl -T -a "certvalid" \
	-y "${srcdir}/tls-certs/ossl-server-certchain.pem" \
	-z "${srcdir}/tls-certs/ossl-server-key.pem" \
	-e "$errorlog"

echo 'Send certificate to server without configured trust anchors...'
if ./send -l openssl -t 127.0.0.1 -p "$TESTPORT" -m "testmessage" \
	-T -a "certvalid" \
	-y "${srcdir}/tls-certs/ossl-client-certchain.pem" \
	-z "${srcdir}/tls-certs/ossl-client-key.pem" \
	-e "$errorlog" $OPT_VERBOSE 1>>"${OUTFILE}" 2>&1; then
	printf 'FAIL: OpenSSL accepted a peer without an explicit trust anchor\n'
	stop_receiver
	exit 1
fi

stop_receiver
check_output "Server handshake failed" "$errorlog"
terminate
