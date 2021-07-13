#!/bin/bash
# This file contains the test framework, that is common code
# used by all tests.
# Copyright (C) 2018 by Rainer Gerhards

# "config settings" for the testbench
TB_TIMEOUT_STARTUP=400  # 40 seconds - Solaris sometimes needs this...
export LIBRELP_DYN="$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head --bytes 4)"
export valgrind="valgrind --malloc-fill=ff --free-fill=fe --log-fd=1"
# **** use the line below for very hard to find leaks! *****
#export valgrind="valgrind --malloc-fill=ff --free-fill=fe --log-fd=1 --leak-check=full --show-leak-kinds=all"
#export OPT_VERBOSE=-v # uncomment for debugging 
source set-envvars

######################################################################
# functions
######################################################################

# finds a free port that we can bind a listener to
# Obviously, any solution is race as another process could start
# just after us and grab the same port. However, in practice it seems
# to work pretty well. In any case, we should probably call this as
# late as possible before the usage of the port.
get_free_port() {
	$PYTHON -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
}

# check if command $1 is available - will exit 77 when not OK
check_command_available() {
	have_cmd=0
	if [ "$1" == "timeout" ]; then
		if timeout --version &>/dev/null ; then
			have_cmd=1
		fi
	else
		if command -v $1 ; then
			have_cmd=1
		fi
	fi
	if [ $have_cmd -eq 0 ] ; then
		printf 'Testbench requires unavailable command: %s\n' "$1"
		exit 77 # do NOT error_exit here!
	fi
}



# $1 is name of pidfile to wait for
wait_process_startup_via_pidfile() {
	i=0
	while test ! -f $1 ; do
		./msleep 100
		(( i++ ))
		if test $i -gt $TB_TIMEOUT_STARTUP
		then
		   printf "ABORT! Timeout waiting on startup, pid file $1\n"
		   exit 1
		fi
	done
	printf "program started up, pidfile $1 contains $(cat $1)\n"
}

# start receiver WITH valgrind, add receiver command line parameters after function name
startup_receiver_valgrind() {
	libtool &> /dev/null
	if [ $? == 127 ]; then
		printf 'libtool command not available, cannot run under valgrind\n'
		exit 77
	fi
	printf 'Starting Receiver...\n'
	libtool --mode=execute $valgrind ./receive $TLSLIB -p $TESTPORT -O $OUTFILE.2 -F $RECEIVE_PIDFILE $OPT_VERBOSE $* &
	export RECEIVE_PID=$!
	printf "got $RECEIVE_PID $RECEIVE_PIDFILE\n"
	wait_process_startup_via_pidfile $RECEIVE_PIDFILE
	printf 'Receiver running\n'
}

# start receiver, add receiver command line parameters after function name
startup_receiver() {
	printf 'Starting Receiver...\n'
	./receive $TLSLIB -p $TESTPORT -F $RECEIVE_PIDFILE -O $OUTFILE $OPT_VERBOSE $* &
	export RECEIVE_PID=$!
	printf "got $RECEIVE_PID $RECEIVE_PIDFILE\n"
	wait_process_startup_via_pidfile $RECEIVE_PIDFILE
	printf 'Receiver running\n'
}

stop_receiver() {
	if [ "$RECEIVE_PID" == "" ]; then
		printf 'oops - receiver pid not found in stop_receiver\n'
		return
	fi
	kill $RECEIVE_PID &> /dev/null
	wait $RECEIVE_PID
	export RECEIVE_EXIT=$?
	printf 'receiver %d stopped\n' $RECEIVE_PID
}

abort_receiver() {
	if [ "$RECEIVE_PID" == "" ]; then
		printf 'oops - receiver pid not found in abort_receiver\n'
		return
	fi
set -x; set +v
	printf 'stopping receiver %d via abort method\n' $RECEIVE_PID
	kill -USR1 $RECEIVE_PID # &> /dev/null
	wait $RECEIVE_PID
	printf 'receiver %d stopped via abort method\n' $RECEIVE_PID
set +x; set +v
}

# $1 is the value to check for
# $2 (optinal) is the file to check
check_output() {
	if [ "$1" == "--check-only" ]; then
		check_only="yes"
		shift
	else
		check_only="no"
	fi

	EXPECTED="$1"
	if [ "$2" == "" ] ; then
		FILE_TO_CHECK="$OUTFILE"
	else
		FILE_TO_CHECK="$2"
	fi

	grep $3 "$EXPECTED" $FILE_TO_CHECK > /dev/null
	if [ $? -ne 0 ]; then
		if [ "$check_only" == "yes" ]; then
			printf 'check_output did not yet succeed for "%s" in "%s" (check_only set)\n', "$EXPECTED", "$FILE_TO_CHECK"
			return 1
		fi
		printf "\nFAIL: expected message not found. Expected:\n"
		printf "%s\n" "$EXPECTED"
		printf "\n$FILE_TO_CHECK actually is:\n"
		cat $FILE_TO_CHECK
		exit 1
	fi
	if [ "$check_only" == "yes" ]; then
		return 0
	fi
}


# wait until $TESTPORT is no longer bound, e.g. for session closure
# TODO: evaluate if this function is really used and, if not,
# TODO: remove again - 2018-11-19 rgerhards
wait_testport_available() {
	while true; do
		printf 'checking NETSTAT\n'
		if ! netstat -tp | grep -q $TESTPORT; then
			break
		fi
		./msleep 1000
	done
}


# $1 is the value to check for
# $2 (optinal) is the file to check
check_output_only() {
	EXPECTED="$1"
	if [ "$2" == "" ] ; then
		FILE_TO_CHECK="$OUTFILE"
	else
		FILE_TO_CHECK="$2"
	fi
#	printf "\ncheck_output_only on $FILE_TO_CHECK with '$EXPECTED'\n"
	grep -q "$EXPECTED" $FILE_TO_CHECK;
	if [ $? -ne 0 ]; then
		# False
#		printf "\ncheck_output_only FALSE \n";
		return 1;
	else
		# true
#		printf "\ncheck_output_only TRUE \n";
		return 0;
	fi
}

# cleanup temporary
# note: on solaris,
# get full command line: /usr/ucb/ps awwx
# find who listens on port:
# netstat -an | grep $TESTPORT
# ./CI/solaris-findport.sh $TESTPORT
cleanup() {
	if [ "$(uname)" == "SunOS" ] ; then
		pkill -x receive
		echo pkill result $?
	fi

	if [ -f $RECEIVE_PID ]; then
		kill -9 $RECEIVE_PID &> /dev/null
	fi

	rm -f -- $DYNNAME* *.err.log error.*.log
	rm -rf $TESTDIR
}

# cleanup at end of regular test run
terminate() {
	cleanup
	printf "%s %s SUCCESS\n" "$(date +%H:%M:%S)" "$0"
}

# check that the output file contains correct number of messages
# Works on $OUTFILE
# TODO: check sequence, so that we do not have duplicates...
check_msg_count() {
	printf 'We have %s lines in %s\n' $(wc -l < $OUTFILE) $OUTFILE
	if ! ./chkseq -s1 -e$NUMMESSAGES -f$OUTFILE -d ; then
		exit 1
	fi
	return
	lines=$(wc -l < $OUTFILE)
	if [ "$lines" -ne $NUMMESSAGES ]; then
		printf 'FAIL: message count not correct for %s\n' $OUTFILE
		printf 'Have %s lines, expected %d\n' "$lines" $NUMMESSAGES
		exit 1
	fi
}

# execute tls tests with currently enabled TLS libraries
# the actual test to be carried out must be defined as "actual_test"
# the tlslib is passed the to it via env var TEST_TLS_LIB
do_tls_subtests() {
	export TEST_TLS_LIB
	for TEST_TLS_LIB in "gnutls" "openssl"; do
		if ./have_tlslib $TEST_TLS_LIB; then
			printf '\nBEGIN SUBTEST using TLS lib: %s\n' $TEST_TLS_LIB
			actual_test
		else
			printf '\nskipping %s lib, not supported in this build\n' $TEST_TLS_LIB
		fi
	done
}

######################################################################
# testbench initialization code - do this LAST here in the file
######################################################################
printf "============================================================\n"
printf "%s: Test: $0\n" "$(date +%H:%M:%S)"
printf "============================================================\n"

export TESTPORT=$(get_free_port)
export DYNNAME=lrtb_${TESTPORT}.
export TESTDIR=lrtb_${TESTPORT}
mkdir $TESTDIR
export OUTFILE=${TESTDIR}/librelp.out.log
export RECEIVE_PIDFILE=${DYNNAME}receive.pid
