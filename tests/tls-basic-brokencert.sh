#!/bin/bash
. ${srcdir}/test-framework.sh
startup_receiver -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem -y ${srcdir}/tls-certs/ossl-server-cert.pem -z ${srcdir}/tls-certs/ossl-server-key.pem -P 'clientbrok.testbench.rsyslog.com' -e error.out.log

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ossl-ca.pem -y ${srcdir}/tls-certs/ossl-clientbrok-cert.pem -z ${srcdir}/tls-certs/ossl-clientbrok-key.pem -P 'server.testbench.rsyslog.com' $OPT_VERBOSE 1>>librelp.out.log 2>&1

stop_receiver

if check_output_only "certificate validation failed, names inside certifcate are way to long" error.out.log; then
	printf "\nExpected: certificate validation failed due broken client cert.\n"
else
	printf "\nOpenSSL Version has limited key exchange, broken certs above 32K won't work anyway.\n"
	printf "\nDEBUG: content of librelp.out.log\n"
	cat $FILE_TO_CHECK
	check_output "relpTcpLastSSLErrorMsg\: Errorstack\: error\:.*\:excessive message size" error.out.log
fi

terminate
