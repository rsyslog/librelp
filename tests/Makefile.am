TEST_EXTENSIONS=.sh
check_PROGRAMS=receive send chkseq have_tlslib msleep

if ENABLE_TLS_OPENSSL
if BUILD_STATIC
# This white-box test needs internal symbols that are not exported by librelp.
check_PROGRAMS+=tls_ossl_fd_reuse
tls_ossl_fd_reuse_SOURCES=tls-ossl-fd-reuse.c
tls_ossl_fd_reuse_LDADD=../src/.libs/librelp.a $(GNUTLS_LIBS) $(OPENSSL_LIBS) $(rt_libs) $(socket_libs) $(pthread_libs)
tls_ossl_fd_reuse_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)
if OS_SOLARIS_WRAP
else
check_PROGRAMS+=tls_ossl_retry_state
tls_ossl_retry_state_SOURCES=tls-ossl-retry-state.c
tls_ossl_retry_state_LDADD=../src/.libs/librelp.a $(GNUTLS_LIBS) $(OPENSSL_LIBS) $(rt_libs) $(socket_libs) $(pthread_libs)
tls_ossl_retry_state_LDFLAGS=-Wl,--wrap=SSL_write -Wl,--wrap=SSL_read -Wl,--wrap=SSL_get_error
tls_ossl_retry_state_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)
endif
endif
endif

if ENABLE_TLS
if BUILD_STATIC
check_PROGRAMS+=permitted_peer_lifetime
permitted_peer_lifetime_SOURCES=permitted-peer-lifetime.c
permitted_peer_lifetime_LDADD=../src/.libs/librelp.a $(GNUTLS_LIBS) $(OPENSSL_LIBS) $(rt_libs) $(socket_libs) $(pthread_libs)
permitted_peer_lifetime_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)
# These white-box fixtures use GNU ld --wrap interposition. Solaris Studio
# accepts the option but does not provide compatible runtime interposition.
if OS_SOLARIS_WRAP
else
check_PROGRAMS+=tcp_accept_fd_reuse tls_gtls_lifecycle
tcp_accept_fd_reuse_SOURCES=tcp-accept-fd-reuse.c
tcp_accept_fd_reuse_LDADD=../src/.libs/librelp.a $(GNUTLS_LIBS) $(OPENSSL_LIBS) $(rt_libs) $(socket_libs) $(pthread_libs)
tcp_accept_fd_reuse_LDFLAGS=-Wl,--wrap=accept -Wl,--wrap=close
tcp_accept_fd_reuse_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)
tls_gtls_lifecycle_SOURCES=tls-gtls-lifecycle.c
tls_gtls_lifecycle_LDADD=../src/.libs/librelp.a $(GNUTLS_LIBS) $(OPENSSL_LIBS) $(rt_libs) $(socket_libs) $(pthread_libs)
tls_gtls_lifecycle_LDFLAGS=-Wl,--wrap=gnutls_bye -Wl,--wrap=gnutls_deinit \
	-Wl,--wrap=gnutls_certificate_free_credentials \
	-Wl,--wrap=gnutls_anon_free_client_credentials \
	-Wl,--wrap=gnutls_anon_free_server_credentials \
	-Wl,--wrap=gnutls_dh_params_deinit
tls_gtls_lifecycle_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)
endif
endif
endif

receive_SOURCES=receive.c
receive_LDADD=../src/.libs/librelp.la
receive_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)

send_SOURCES=send.c
send_LDADD=../src/.libs/librelp.la
send_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)

msleep_SOURCES = msleep.c

chkseq_SOURCES=chkseq.c
have_tlslib_SOURCES=have_tlslib.c

VALGRIND_TESTS= \
	duplicate-receiver-vg.sh \
	basic-sessionbreak-vg.sh


# TLS tests that work both with gnutls and openssl
TLS_TESTS=  \
	tls-basic.sh \
	tls-basic-realistic.sh \
	tls-basic-anon.sh \
	tls-basic-certvalid.sh \
	tls-gtls-certvalid-no-trust-anchor.sh \
	tls-basic-fingerprint.sh \
	tls-basic-wildcard.sh \
	tls-basic-tlscommand.sh \
	tls-basic-tlscommand-ciphers.sh \
	tls-basic-certchain.sh \
	tls-certvalid-untrusted.sh \
	tls-basic-certvalid-mixed.sh \
	tls-client-auth-no-cert.sh \
	tls-receiver-abort.sh \
	tls-missing-param-sender.sh \
	tls-missing-param-receiver.sh
TLS_VALGRIND_TESTS= \
	tls-basic-vg.sh \
	tls-ossl-connect-failure-vg.sh

# static tests specific to GnuTLS
GTLS_STATIC_TESTS= \
	tcp-accept-fd-reuse.sh \
	tls-gtls-lifecycle.sh
TLS_STATIC_TESTS= \
	permitted-peer-lifetime.sh

# test specific to openssl
OSSL_TESTS= \
	tls-wrong-permittedPeer.sh \
	tls-wrong-authname.sh \
	tls-wrong-signedcert.sh
OSSL_STATIC_TESTS= \
	tls-ossl-fd-reuse.sh
OSSL_WRAP_STATIC_TESTS= \
	tls-ossl-retry-state.sh
# reenable tests when stable
#	tls-basic-brokencert.sh

TESTS=  selftest_receive_watchdog.sh \
	selftest_receive_usage.sh \
	basic.sh \
	basic-realistic.sh \
	session-callbacks.sh \
	receiver-abort.sh \
	long-msg.sh \
	oversize-msg-abort-errmsg.sh \
	oversize-msg-accept-errmsg.sh \
	truncate-oversize-msg.sh \
	send-noconnect.sh \
	send-dummyserver-no-waitstate-errmsg.sh \
	receive-emptyconnect.sh
if ENABLE_TLS_GENERIC
TESTS+=$(TLS_TESTS)
endif
if ENABLE_TLS
if BUILD_STATIC
TESTS+=$(TLS_STATIC_TESTS)
if OS_SOLARIS_WRAP
else
TESTS+=$(GTLS_STATIC_TESTS)
endif
endif
endif
if ENABLE_TLS_OPENSSL
TESTS+=$(OSSL_TESTS)
if BUILD_STATIC
TESTS+=$(OSSL_STATIC_TESTS)
if OS_SOLARIS_WRAP
else
TESTS+=$(OSSL_WRAP_STATIC_TESTS)
endif
TESTS+=tls-openssl-retry-state.sh
check_PROGRAMS+=tls-openssl-retry-state

tls_openssl_retry_state_SOURCES=tls-openssl-retry-state.c ../src/tcp.c
tls_openssl_retry_state_LDADD=../src/.libs/librelp.a $(GNUTLS_LIBS) $(OPENSSL_LIBS) $(rt_libs) $(socket_libs) $(pthread_libs)
tls_openssl_retry_state_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)
tls_openssl_retry_state_CPPFLAGS=-DTEST_CERT_DIR=\"$(srcdir)/tls-certs\"
endif
endif

if HAVE_VALGRIND
TESTS+=$(VALGRIND_TESTS)
if ENABLE_TLS_GENERIC
TESTS+=$(TLS_VALGRIND_TESTS)
endif # ENABLE_TLS_GENERIC
endif # HAVE_VALGRIND

EXTRA_DIST=$(TESTS) \
	$(TLS_TESTS) \
	$(GTLS_STATIC_TESTS) \
	$(OSSL_TESTS) \
	$(OSSL_STATIC_TESTS) \
	$(OSSL_WRAP_STATIC_TESTS) \
	$(TLS_VALGRIND_TESTS) \
	$(VALGRIND_TESTS) \
	set-envvars.in \
	dummyclient.py \
	dummyserver.py \
	invalid-open.py \
	session-callbacks.sh \
	test-framework.sh \
	receive.c \
	send.c \
	tls-ossl-fd-reuse.c \
	tls-ossl-retry-state.c \
	tcp-accept-fd-reuse.c \
	tls-gtls-lifecycle.c \
	permitted-peer-lifetime.c \
	tls-openssl-retry-state.sh \
	tls-openssl-retry-state.c \
	tls-certs/ca.pem \
	tls-certs/cert.pem \
	tls-certs/key.pem \
	tls-certs/certchain.pem \
	tls-certs/ossl-ca.pem \
	tls-certs/ossl-ca-key.pem \
	tls-certs/ossl-client-cert.pem \
	tls-certs/ossl-client-key.pem \
	tls-certs/ossl-client-certchain.pem \
	tls-certs/ossl-clientbrok-cert.pem \
	tls-certs/ossl-clientbrok-key.pem \
	tls-certs/ossl-server-cert.pem \
	tls-certs/ossl-server-key.pem \
	tls-certs/ossl-server-certchain.pem
