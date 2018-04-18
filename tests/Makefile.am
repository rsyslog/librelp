check_PROGRAMS=receive send

receive_SOURCES=receive.c
#receive_LDADD=-lrelp
receive_LDADD=../src/.libs/librelp.la
receive_CFLAGS=-I${top_srcdir}/src

send_SOURCES=send.c
#send_LDADD=-lrelp
send_LDADD=../src/.libs/librelp.la
send_CFLAGS=-I${top_srcdir}/src

VALGRIND_TESTS= \
	tls-basic-vg.sh

TESTS=  basic.sh \
	tls-basic.sh \
	tls-basic-anon.sh \
	tls-wrong-permittedPeer.sh \
	tls-wrong-authname.sh \
	tls-missing-param-sender.sh \
	tls-missing-param-receiver.sh \
	long-msg.sh \
	oversize-msg-abort-errmsg.sh \
	truncate-oversize-msg.sh

if HAVE_VALGRIND
TESTS += $(VALGRIND_TESTS)
endif

EXTRA_DIST=$(TESTS) \
	$(VALGRIND_TESTS) \
	test-framework.sh \
	receive.c \
	send.c \
	tls-certs/ca.pem \
	tls-certs/cert.pem \
	tls-certs/key.pem
