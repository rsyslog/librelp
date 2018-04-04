#!/bin/bash

echo 'relp-tls-basic.sh'
echo '================='

TESTPORT=20514

echo 'Start Receiver...'
./receive -p $TESTPORT -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog" > librelp.out.log &
PID=$!

sleep 1

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog"


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
exit


