#!/bin/bash
# checks if server handles connection request by clients which are immediately
# closed (without sending data) validly. This also means an error message must
# be emitted. This situation can frequently happen in Proxy configurations.
# written 2018-11-20 by Rainer Gerhards, released under ASL 2.0
. ${srcdir:=$(pwd)}/test-framework.sh
export errorlog="error.$LIBRELP_DYN.log"
check_command_available timeout

startup_receiver -e $TESTDIR/$errorlog
timeout 10s $PYTHON ${srcdir}/dummyclient.py
sleep 1
stop_receiver
# TODO: we should word the error message clearer, then also change here
check_output "server closed relp session" $TESTDIR/$errorlog
terminate
