#!/bin/bash
# run compile-only tests under Travis
# This is specifically written to support Travis CI
set -e
if [ "$PROJ_HOME" == "" ]; then
	export PROJ_HOME=$(pwd)
	echo info: PROJ_HOME not set, using $PROJ_HOME
fi

DO_IN_CONTAINER="$PROJ_HOME/devtools/devcontainer.sh"
printf "\n\n============ STEP: check code style ================\n\n\n"
$DO_IN_CONTAINER devtools/check-codestyle.sh


echo ==================== compile using gnutls ====================
export PROJ_CONFIGURE_OPTIONS=--enable-tls


printf "\n\n============ STEP: run static analyzer ================\n\n\n"
$DO_IN_CONTAINER devtools/run-static-analyzer.sh

# #################### newer compilers ####################

printf "\n\n============ STEP: gcc-7 compile test ================\n\n\n"
export CC=gcc-7
export CFLAGS=
$DO_IN_CONTAINER devtools/run-configure.sh
$DO_IN_CONTAINER make check TESTS=""

$DO_IN_CONTAINER make clean
printf "\n\n============ STEP: clang-5.0 compile test ================\n\n\n"
export CC=clang-5.0
export CFLAGS=
$DO_IN_CONTAINER devtools/run-configure.sh
$DO_IN_CONTAINER make check TESTS=""

exit 0

# #################### older style compile tests####################
$DO_IN_CONTAINER make clean
printf "\n\n============ STEP: testing alpine build  ================\n\n\n"
$PROJ_HOME/tests/travis/docker-alpine.sh



echo ==================== compile using openssl ====================
export PROJ_CONFIGURE_OPTIONS=--enable-tls-openssl


printf "\n\n============ STEP: run static analyzer ================\n\n\n"
$DO_IN_CONTAINER make clean
$DO_IN_CONTAINER devtools/run-static-analyzer.sh

# #################### newer compilers ####################

printf "\n\n============ STEP: gcc-7 compile test ================\n\n\n"
export CC=gcc-7
export CFLAGS=
$DO_IN_CONTAINER devtools/run-configure.sh
$DO_IN_CONTAINER make check TESTS=""


exit 0

# #################### older style compile tests####################
$DO_IN_CONTAINER make clean
printf "\n\n============ STEP: testing alpine build  ================\n\n\n"
$PROJ_HOME/tests/travis/docker-alpine.sh
