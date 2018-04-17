#!/bin/bash
set -e
find . -name "*.[ch]" | xargs rsyslog_stylecheck
