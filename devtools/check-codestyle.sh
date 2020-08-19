#!/bin/bash
set -e
find . -type f \( -iname "*.[ch]" ! -iname "config.h" \) -exec rsyslog_stylecheck {} +
