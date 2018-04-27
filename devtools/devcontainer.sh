#!/bin/bash
# This scripts uses an rsyslog development container to execute given
# command inside it.
# Note that we "abuse" the /rsyslog path a bit by placing our project
# in there.
set -e

if [ "$PROJ_HOME" == "" ]; then
	export PROJ_HOME=$(pwd)
	echo info: PROJ_HOME not set, using $PROJ_HOME
fi

DEV_CONTAINER=`cat $PROJ_HOME/devtools/default_dev_container`

printf "/rsyslog is mapped to $PROJ_HOME\n"
docker pull $DEV_CONTAINER
docker run \
	-u `id -u`:`id -g` \
	-e PROJ_CONFIGURE_OPTIONS_EXTRA \
	-e CC \
	-e CFLAGS \
	$DOCKER_RUN_EXTRA_FLAGS \
	-v "$PROJ_HOME":/rsyslog $DEV_CONTAINER  $*
