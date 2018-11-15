#!/bin/bash
if [ $(uname) = "SunOS" ] ; then
   echo "This test currently does not work on all flavors of Solaris."
   exit 77
fi
if [ $(uname) = "FreeBSD" ] ; then
   echo "This test currently does not work on FreeBSD."
   exit 77
fi

. ${srcdir}/test-framework.sh

startup_receiver_valgrind

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage"

stop_receiver
check_output "testmessage"
terminate
