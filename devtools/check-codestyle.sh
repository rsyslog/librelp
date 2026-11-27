#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -e
find . -type f \( -iname "*.[ch]" ! -iname "config.h" \) -exec rsyslog_stylecheck {} +
