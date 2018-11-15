#!/bin/bash
set -e
find . -name "*.[ch]" -exec rsyslog_stylecheck {} +
