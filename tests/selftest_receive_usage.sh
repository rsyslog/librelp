#!/bin/bash
. ${srcdir:=$(pwd)}/test-framework.sh
./receive &>${OUTFILE}
cat ${OUTFILE}
check_output "Port is missing"
terminate
