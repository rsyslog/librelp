#!/bin/bash
# check that failed connect to receiver is gracefully handled and error
# message emitted.
# written 2018-11-20 by Rainer Gerhards, released under ASL 2.0
. ${srcdir:=$(pwd)}/test-framework.sh
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" $OPT_VERBOSE &> librelp.out.log

check_output "error opening connection"
terminate
