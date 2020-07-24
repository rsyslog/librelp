#!/bin/bash
# This is a self test for the testbench! It does NOT test Relp.
. ${srcdir:=$(pwd)}/test-framework.sh

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -y ${srcdir}/tls-certs/cert.pem  -P "rsyslog" > ${OUTFILE}

check_output "send:.*parameter missing; certificates and permittedPeer required"
terminate
