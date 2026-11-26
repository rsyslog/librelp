#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

TLSLIB="-l gnutls"
errorlog="$TESTDIR/error.out.log"
sha256_fingerprint='SHA256:1E:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6'

startup_receiver -T -a "fingerprint" -x ${srcdir}/tls-certs/ca.pem \
	-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
	-P "$sha256_fingerprint" -e "$errorlog"

if ./send $TLSLIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T \
	-a "fingerprint" -x ${srcdir}/tls-certs/ca.pem \
	-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
	-P "$sha256_fingerprint" -e "$errorlog" -v $OPT_VERBOSE 1>>${OUTFILE} 2>&1; then
	stop_receiver
	printf 'FAIL: reduced GnuTLS fingerprint mode accepted a SHA256 pin\n'
	exit 1
fi

stop_receiver
check_output "unsupported GnuTLS fingerprint digest" "$OUTFILE"
if grep -F "peer's certificate SHA1 fingerprint:" "$OUTFILE" > /dev/null; then
	printf 'FAIL: reduced GnuTLS fingerprint mode tried SHA1 after rejecting a SHA256 pin\n'
	exit 1
fi
terminate
