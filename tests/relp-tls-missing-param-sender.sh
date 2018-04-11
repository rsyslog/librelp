#!/bin/bash

echo 'relp-tls-missing-param-sender.sh'
echo '================================'

TESTPORT=20514

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" -T -a "name" -y ${srcdir}/tls-certs/cert.pem -z ${srcdir}/tls-certs/key.pem -P "rsyslog" > librelp.out.log


grep "send: parameter missing; certificates and permittedPeer required" librelp.out.log > /dev/null
if [ $? -ne 0 ]; then
        echo
        echo "FAIL: expected message not found. librelp.out.log is:"
        cat librelp.out.log
        exit 1
fi

echo '--------------------------------------------------------------------'
rm librelp.out.log
exit


