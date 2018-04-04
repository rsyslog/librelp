#!/bin/bash

echo 'relp-tls-wrong-authname.sh'
echo '=========================='

TESTPORT=20514

echo 'Start Receiver...'
./receive -p $TESTPORT -T -a "anon" -x tls-certs/ca.pem -y tls-certs/cert.pem -z tls-certs/key.pem -P "rsyslog" &
PID=$!

sleep 1

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "anon" -x tls-certs/ca.pem -y tls-certs/cert.pem -z tls-certs/key.pem -P "rsyslog" -v 2>&1 | tee sender.out.log


echo 'Stop Receiver...'
kill $PID


grep "relpCltSetAuthMode(pRelpClt, authMode)" sender.out.log > /dev/null
if [ $? -ne 0 ]; then
        echo
        echo "FAIL: expected message not found. sender.out.log is:"
        cat sender.out.log
        exit 1
fi

echo '--------------------------------------------------------------------'
rm sender.out.log
exit


