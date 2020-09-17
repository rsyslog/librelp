#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
export errorlog="error.$LIBRELP_DYN.log"

# NOT USING startup_receiver here!
ls -ld $TESTDIR
echo outfile: $OUTFILE
./receive -p $TESTPORT -T -a "anon" \
	-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem \
	-P "rsyslog" $OPT_VERBOSE $* 1>>${OUTFILE} 2>&1
check_output "relpSrvSetAuthMode(pRelpSrv, authMode)"
printf 'Server check OK\n'

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "anon" \
	2> $TESTDIR/$errorlog \
	-x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem \
	-z ${srcdir}/tls-certs/key.pem -P "rsyslog" $OPT_VERBOSE
check_output "relpCltSetAuthMode(pRelpClt, authMode)" $TESTDIR/$errorlog
terminate
