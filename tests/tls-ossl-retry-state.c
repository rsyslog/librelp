/*
 * Deterministic reproducer for stale OpenSSL retry state.
 *
 * The production reproducer fills a TLS receiver's send window until
 * SSL_write() returns WANT_WRITE. Once the connection becomes writable, the
 * retry succeeds but the old state remained set, pinning the event loop to
 * EPOLLOUT and making it spin over an empty send queue. The wrappers below
 * reproduce that exact WANT-to-success transition without timing or load.
 */
#include "config.h"

#if defined(ENABLE_TLS_OPENSSL)

#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>

#include "librelp.h"
#include "tcp.h"

enum operation {
	OP_SEND_WANT,
	OP_SEND_SUCCESS,
	OP_RECV_WANT,
	OP_RECV_SUCCESS
};

static enum operation current_operation;

int __wrap_SSL_write(SSL *ssl, const void *buf, int num);
int __wrap_SSL_read(SSL *ssl, void *buf, int num);
int __wrap_SSL_get_error(const SSL *ssl, int ret);

int
__wrap_SSL_write(SSL *const ssl __attribute__((unused)), const void *const buf __attribute__((unused)), const int num)
{
	return current_operation == OP_SEND_WANT ? -1 : num;
}

int
__wrap_SSL_read(SSL *const ssl __attribute__((unused)), void *const buf, const int num)
{
	if(current_operation == OP_RECV_WANT)
		return -1;
	if(num > 0)
		((unsigned char *) buf)[0] = 'x';
	return num > 0 ? 1 : 0;
}

int
__wrap_SSL_get_error(const SSL *const ssl __attribute__((unused)), const int ret __attribute__((unused)))
{
	return current_operation == OP_SEND_WANT ? SSL_ERROR_WANT_WRITE : SSL_ERROR_WANT_READ;
}

static void
discard_debug(char *const fmt __attribute__((unused)), ...)
{
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpTcp_t *tcp = NULL;
	relpOctet_t data[8] = {0};
	ssize_t len;
	int rc = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK
	   || relpEngineSetDbgprint(engine, discard_debug) != RELP_RET_OK
	   || relpEngineSetTLSLibByName(engine, "openssl") != RELP_RET_OK
	   || relpTcpConstruct(&tcp, engine, RELP_CLT_CONN, NULL) != RELP_RET_OK) {
		fprintf(stderr, "failed to construct librelp test objects\n");
		goto done;
	}

	tcp->bEnableTLS = 1;
	tcp->ssl = (SSL *) tcp; /* wrappers do not dereference the test token */

	current_operation = OP_SEND_WANT;
	len = sizeof(data);
	if(relpTcpSend(tcp, data, &len) != RELP_RET_OK || len != 0
	   || tcp->rtryOp != relpTCP_RETRY_send) {
		fprintf(stderr, "SSL WANT_WRITE did not establish send retry state\n");
		goto done;
	}

	current_operation = OP_SEND_SUCCESS;
	len = sizeof(data);
	if(relpTcpSend(tcp, data, &len) != RELP_RET_OK || len != (ssize_t) sizeof(data)
	   || tcp->rtryOp != relpTCP_RETRY_none) {
		fprintf(stderr, "successful SSL_write left stale send retry state\n");
		goto done;
	}

	current_operation = OP_RECV_WANT;
	len = sizeof(data);
	if(relpTcpRcv(tcp, data, &len) != RELP_RET_OK || len != -1
	   || tcp->rtryOp != relpTCP_RETRY_recv) {
		fprintf(stderr, "SSL WANT_READ did not establish receive retry state\n");
		goto done;
	}

	current_operation = OP_RECV_SUCCESS;
	len = sizeof(data);
	if(relpTcpRcv(tcp, data, &len) != RELP_RET_OK || len != 1
	   || tcp->rtryOp != relpTCP_RETRY_none) {
		fprintf(stderr, "successful SSL_read left stale receive retry state\n");
		goto done;
	}

	printf("OpenSSL retry state cleared after successful I/O\n");
	rc = EXIT_SUCCESS;

done:
	if(tcp != NULL) {
		tcp->ssl = NULL;
		(void) relpTcpDestruct(&tcp);
	}
	if(engine != NULL)
		(void) relpEngineDestruct(&engine);
	return rc;
}

#else

int
main(void)
{
	return 77;
}

#endif
