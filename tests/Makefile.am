TEST_EXTENSIONS=.sh
check_PROGRAMS=receive send chkseq have_tlslib

receive_SOURCES=receive.c
receive_LDADD=../src/.libs/librelp.la
receive_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)

send_SOURCES=send.c
send_LDADD=../src/.libs/librelp.la
send_CFLAGS=$(AM_CFLAGS) -I${top_srcdir}/src $(WARN_CFLAGS)

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
	tls-basic-fingerprint.sh \
	tls-basic-wildcard.sh \
	tls-basic-tlscommand.sh \
	tls-receiver-abort.sh \
	tls-missing-param-sender.sh \
	tls-missing-param-receiver.sh
TLS_VALGRIND_TESTS= \
	tls-basic-vg.sh

# test specific to openssl
OSSL_TESTS= \
	tls-wrong-permittedPeer.sh \
	tls-wrong-authname.sh \
	tls-wrong-signedcert.sh
# reenable tests when stable
#	tls-basic-brokencert.sh

TESTS=  selftest_receive_watchdog.sh \
	selftest_receive_usage.sh \
	basic.sh \
	basic-realistic.sh \
	receiver-abort.sh \
	long-msg.sh \
	oversize-msg-abort-errmsg.sh \
	oversize-msg-accept-errmsg.sh \
	truncate-oversize-msg.sh \
	send-noconnect.sh \
	receive-emptyconnect.sh
if ENABLE_TLS_GENERIC
TESTS+=$(TLS_TESTS)
endif
if ENABLE_TLS_OPENSSL
TESTS+=$(OSSL_TESTS)
endif

if HAVE_VALGRIND
TESTS+=$(VALGRIND_TESTS)
if ENABLE_TLS_GENERIC
TESTS+=$(TLS_VALGRIND_TESTS)
endif # ENABLE_TLS_GENERIC
endif # HAVE_VALGRIND

EXTRA_DIST=$(TESTS) \
	$(TLS_TESTS) \
	$(OSSL_TESTS) \
	$(TLS_VALGRIND_TESTS) \
	$(VALGRIND_TESTS) \
	dummyclient.py \
	dummyserver.py \
	test-framework.sh \
	receive.c \
	send.c \
	tls-certs/ca.pem \
	tls-certs/cert.pem \
	tls-certs/key.pem \
	tls-certs/ossl-ca.pem \
	tls-certs/ossl-ca-key.pem \
	tls-certs/ossl-client-cert.pem \
	tls-certs/ossl-client-key.pem \
	tls-certs/ossl-clientbrok-cert.pem \
	tls-certs/ossl-clientbrok-key.pem \
	tls-certs/ossl-server-cert.pem \
	tls-certs/ossl-server-key.pem

