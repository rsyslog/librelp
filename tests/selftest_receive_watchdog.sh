#!/bin/bash
# written 2018-11-28 by Rainer Gerhards, released under ASL 2.0
. ${srcdir:=$(pwd)}/test-framework.sh
printf 'starting receive, waiting for watchdog timeout to occur\n'
./receive --watchdog-timeout 2 -p $TESTPORT &> $OUTFILE
cat $OUTFILE
check_output "watchdog timer expired"
terminate
