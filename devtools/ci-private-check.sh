#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Container-side checks for private copies of this repository, called from
# .github/workflows/private_container.yml via devtools/devcontainer.sh.
# They replace the host-build jobs (coverage asan, no_tls, distcheck), which
# would install packages on the shared self-hosted runners.
# usage: ci-private-check.sh asan|no_tls|distcheck
set -e
case "$1" in
asan)
	export CC=clang
	export CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
	export LDFLAGS="-fsanitize=address,undefined"
	export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
	export LSAN_OPTIONS=exitcode=23
	export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
	conf="--enable-tls --enable-tls-openssl --enable-valgrind=no"
	target=check
	;;
no_tls)
	# Same warning level as the public no_tls job, which builds without
	# autoconf-archive and so without -Werror.
	conf="--disable-tls --disable-tls-openssl --enable-compile-warnings=yes"
	target=check
	;;
distcheck)
	conf="--enable-tls --enable-tls-openssl"
	target=distcheck
	;;
*)
	echo "unknown check '$1'" >&2
	exit 2
	;;
esac
autoreconf -fvi
./configure $conf
make -j"$(nproc)"
rc=0
make -j4 "$target" || rc=$?
if [ "$rc" -ne 0 ]; then
	devtools/gather-check-logs.sh || true
	cat failed-tests.log 2>/dev/null || true
fi
exit "$rc"
