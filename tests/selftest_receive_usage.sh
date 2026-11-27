#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
. ${srcdir:=$(pwd)}/test-framework.sh
./receive &>${OUTFILE}
cat ${OUTFILE}
check_output "Port is missing"
terminate
