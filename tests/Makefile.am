check_PROGRAMS=receive send

receive_SOURCES=receive.c
#receive_LDADD=-lrelp
receive_LDADD=../src/.libs/librelp.la
receive_CFLAGS=-I${top_srcdir}/src

send_SOURCES=send.c
#send_LDADD=-lrelp
send_LDADD=../src/.libs/librelp.la
send_CFLAGS=-I${top_srcdir}/src

TESTS=  relp-basic.sh \
	relp-tls-basic.sh \
	relp-tls-basic-anon.sh \
	relp-tls-basic-vg.sh \
	relp-tls-wrong-permittedPeer.sh \
	relp-tls-wrong-authname.sh \
	relp-tls-missing-param-sender.sh \
	relp-tls-missing-param-receiver.sh
EXTRA_DIST=$(TESTS) \
	receive.c \
	send.c \
	tls-certs/ca.pem \
	tls-certs/cert.pem \
	tls-certs/key.pem
