#!/bin/bash
# added 2018-11-15 by Rainer Gerhards, released under ASL 2.0
# check that receiver abort is handled gracefully
# of messages
. ${srcdir:=$(pwd)}/test-framework.sh
# export OPT_VERBOSE=-v # uncomment for debugging 
export errorlog="error.$LIBRELP_DYN.log"
export NUMMESSAGES=100000
check_command_available timeout

startup_receiver -e ${TESTDIR}/${errorlog}
./send -t 127.0.0.1 -p $TESTPORT -n$NUMMESSAGES -N -K 20000 -I $RECEIVE_PID $OPT_VERBOSE &
SENDER_PID=$!

for i in {1..3};  do
	sleep 2
	timeout 10s $PYTHON ${srcdir}/dummyserver.py $TESTPORT
done

sleep 2 # make sure client goes into retry

startup_receiver --append-outfile
wait $SENDER_PID
printf 'wait on sender retured %d\n' $?
stop_receiver

check_msg_count
terminate
