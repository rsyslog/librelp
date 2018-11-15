#!/bin/bash
# added 2018-11-15 by Rainer Gerhards, released under ASL 2.0
# a more relastic test which actually sends a bit larger number
# of messages
. ${srcdir:=$(pwd)}/test-framework.sh
NUMMESSAGES=50000
startup_receiver $OPT_VERBOSE
./send -t 127.0.0.1 -p $TESTPORT -n$NUMMESSAGES $OPT_VERBOSE
stop_receiver
check_msg_count
terminate
