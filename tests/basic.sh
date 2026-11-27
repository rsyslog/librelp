#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
. ${srcdir:=$(pwd)}/test-framework.sh
startup_receiver $OPT_VERBOSE

echo 'Send Message...'
./send -t 127.0.0.1 -p $TESTPORT -m "testmessage" $OPT_VERBOSE

stop_receiver
check_output "testmessage"
terminate
