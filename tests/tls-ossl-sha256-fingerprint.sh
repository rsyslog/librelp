#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

export TLSLIB="-l openssl"

sha1_pin='SHA1:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3'
sha256_pin='SHA256:1E:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6'
sha256_mismatch='SHA256:1E:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F7'
sha256_with_sha1='SHA256:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3'
unknown_digest="SHA512:${sha1_pin#SHA1:}"

run_fingerprint_pair() {
	receiver_pin="$1"
	sender_pin="$2"
	errorlog="$TESTDIR/${LIBRELP_DYN}-$3.log"

	startup_receiver -T -a "fingerprint" -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P "$receiver_pin" -e "$errorlog"

	./send $TLSLIB -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T \
		-a "fingerprint" -x ${srcdir}/tls-certs/ca.pem \
		-y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
		-P "$sender_pin" -e "$errorlog" $OPT_VERBOSE 1>>${OUTFILE} 2>&1

	stop_receiver
}

run_fingerprint_pair "$sha256_pin" "$sha256_pin" "sha256-positive"
check_output "testmessage"

run_fingerprint_pair "$sha256_mismatch" "$sha256_pin" "sha256-mismatch"
check_output "authentication error.*non-permited fingerprint.*object '$sha256_pin'" \
	"$TESTDIR/${LIBRELP_DYN}-sha256-mismatch.log"

# A SHA1 value labeled SHA256 must not be accepted by falling back to SHA1.
run_fingerprint_pair "$sha256_with_sha1" "$sha256_pin" "sha256-no-downgrade"
check_output "authentication error.*non-permited fingerprint.*object '$sha256_pin'" \
	"$TESTDIR/${LIBRELP_DYN}-sha256-no-downgrade.log"

run_fingerprint_pair "$unknown_digest" "$sha256_pin" "unknown-digest"
check_output "authentication error.*unsupported configured fingerprint digest in pin 'SHA512:.*'; supported: SHA1, SHA256.*object ''" \
	"$TESTDIR/${LIBRELP_DYN}-unknown-digest.log"

terminate
