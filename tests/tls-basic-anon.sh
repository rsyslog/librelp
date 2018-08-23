#!/bin/bash
. ${srcdir}/test-framework.sh
startup_receiver -T -e error.out.log

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T $OPT_VERBOSE 1>>librelp.out.log 2>&1

# "relpTcpLastSSLErrorMsg: Errorstack: error:1417A0C1:SSL routines:tls_post_process_client_hello:no shared cipher"
stop_receiver
if check_output_only "relpTcpLastSSLErrorMsg\: Errorstack\: error\:.*\:no shared cipher"; then
	printf "\nSKIP: openssl reported 'no shared cipher'\n"
	printf "\nDEBUG: content of librelp.out.log\n"
	cat $FILE_TO_CHECK

	terminate
	exit 77; 
fi

check_output "testmessage"
terminate
