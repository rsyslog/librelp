#!/bin/bash
# checks if server handles connection request by clients which are immediately
# closed (without sending data) validly. This also means an error message must
# be emitted. This situation can frequently happen in Proxy configurations.
# written 2018-11-20 by Rainer Gerhards, released under ASL 2.0
. ${srcdir:=$(pwd)}/test-framework.sh
startup_receiver $OPT_VERBOSE &> $OUTFILE
${srcdir}/dummyclient.py
stop_receiver
# TODO: we should word the error message clearer, then also change here
check_output "server closed relp session"
terminate
