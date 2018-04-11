#!/bin/bash

echo 'relp-tls-wrong-permittedPeer.sh'
echo '==============================='

TESTPORT=20514

echo 'Start Receiver...'
ls -l ${srcdir}/tls-certs/
./receive -p $TESTPORT -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "wrong name" &
PID=$!

sleep 1

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -x ${srcdir}/tls-certs/ca.pem -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "wrong name" -v 2>&1 | tee sender.out.log


echo 'Stop Receiver...'
kill $PID


grep "librelp: auth error: authdata:'DNSname: rsyslog; ', ecode 10034, emsg 'no permited name found'" sender.out.log > /dev/null
if [ $? -ne 0 ]; then
        echo
        echo "FAIL: expected message not found. sender.out.log is:"
        cat sender.out.log
        exit 1
fi

echo '--------------------------------------------------------------------'

rm sender.out.log
exit


