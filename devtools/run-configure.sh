#!/bin/bash
printf "running configure with\nCC:\t$CC\nCFLAGS:\t$CFLAGS\n"
autoreconf -fvi
CFLAGS="-g" ./configure $PROJ_CONFIGURE_OPTIONS
