#!/bin/bash
printf "running configure with\nCC:\t$CC\nCFLAGS:\t$CFLAGS\n"
autoreconf -fvi
./configure $PROJ_CONFIGURE_OPTIONS
