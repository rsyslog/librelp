#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
./receive &>librelp.out.log
cat librelp.out.log
check_output "Port is missing"
terminate
