#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh

ERROR_FILE=${TESTDIR}/dummyserver-error.log

timeout 10s $PYTHON ${srcdir}/dummyserver.py $TESTPORT >${TESTDIR}/dummyserver.log 2>&1 &
DUMMYSERVER_PID=$!

./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -e ${ERROR_FILE} >${TESTDIR}/send.log 2>&1 || true
wait $DUMMYSERVER_PID || true

check_output "send: FAILURE in 'relpCltConnect'" ${TESTDIR}/send.log
check_output "send: error 'server closed relp session, session broken'" ${ERROR_FILE}
check_output "send: error 'error opening connection to remote peer'" ${ERROR_FILE}

if check_output_only "error waiting on required session state" ${ERROR_FILE}; then
	printf 'FAIL: unexpected wait-state error in %s\n' "${ERROR_FILE}"
	cat "${ERROR_FILE}"
	exit 1
fi

terminate
