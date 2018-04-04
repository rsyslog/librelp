#!/bin/bash

set -o xtrace
echo 'relp-tls-basic-anon.sh'
echo '======================'

TESTPORT=20514
TIMEOUT_STARTSTOP=50

echo 'Start Receiver...'
./receive -p $TESTPORT -T -F receive.pid -v > librelp.out.log &
PID=$!
echo "startup, pid as of bash $PID"
while test ! -f receive.pid; do
	sleep .100
	let "i++"
	if test $i -gt $TB_TIMEOUT_STARTSTOP
	then
	   echo "ABORT! Timeout waiting on receiver startup"
	   exit 1
	fi
done
echo "receiver started up, pid " `cat receive.pid`
sleep 1

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -v


echo 'Stop Receiver...'
kill $PID


grep "testmessage" librelp.out.log > /dev/null
if [ $? -ne 0 ]; then
        echo
        echo "FAIL: expected message not found. librelp.out.log is:"
        cat librelp.out.log
        exit 1
fi

echo '--------------------------------------------------------------------'
rm librelp.out.log
rm receive.pid
exit
