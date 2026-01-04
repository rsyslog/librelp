#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

CALLBACK_FILE=${TESTDIR}/session-callbacks.log

startup_receiver -C ${CALLBACK_FILE} $OPT_VERBOSE

./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" $OPT_VERBOSE

$PYTHON ${srcdir}/invalid-open.py

stop_receiver

check_output "testmessage"
check_output "session opened" ${CALLBACK_FILE}
check_output "session closed reason=" ${CALLBACK_FILE}
check_output "session open failed reason=" ${CALLBACK_FILE}
terminate
