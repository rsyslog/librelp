#!/bin/bash
# This test checks that when a second receiver is started it properly
# terminates.
cat << EOF
This test currently does not do anything really useful. We should
either change that or drop the test.
I assume it shall test that librelp does not segfault if the
listen port cannot be bound to.
EOF
exit 77
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


startup_receiver_valgrind # note: two receivers are started intentionally
startup_receiver_valgrind

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage"

stop_receiver
check_output "testmessage"
terminate
