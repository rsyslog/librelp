#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
check_command_available valgrind

if [ "$VALGRIND" == "NO" ] ; then
   echo "valgrind tests are not permitted by environment config"
   exit 77
fi
if [ $(uname) = "SunOS" ] ; then
   echo "This test currently does not work on all flavors of Solaris."
   exit 77
fi
if [ $(uname) = "FreeBSD" ] ; then
   echo "This test currently does not work on FreeBSD."
   exit 77	
fi
export NUMMESSAGES=100000
export NUMLOOPS=2

#export valgrind="valgrind --malloc-fill=ff --free-fill=fe --log-fd=1"
export valgrind="valgrind --malloc-fill=ff --free-fill=fe --leak-check=full --log-fd=1 --error-exitcode=10 --gen-suppressions=all --suppressions=$srcdir/known_issues.supp"
	
startup_receiver_valgrind -N -e error.out.log -O $OUTFILE

echo 'Send Message(s)...'
for i in $(seq 1 $NUMLOOPS); do 
        # How many times tcpflood runs in each threads
	libtool --mode=execute ./send -N -t 127.0.0.1 -p $TESTPORT -m "testmessage" -n $NUMMESSAGES $OPT_VERBOSE &
	send_pid=$!

	echo "started send instance $i (PID $send_pid)"

	# Give it time to actually connect
	sleep 1;

	kill -9 $send_pid # >/dev/null 2>&1;
	echo "killed send instance $i (PID $send_pid)"
done;

stop_receiver

if [ "$RECEIVE_EXIT" -eq "10" ]; then
	cleanup
	printf 'valgrind run FAILED with exceptions\n'
	printf "%s %s FAIL\n" "$(date +%H:%M:%S)" "$0"
	exit 1
fi

#	check_output "testmessage"

terminate
