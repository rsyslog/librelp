/*
 * Regression test for OpenSSL send retry state. An SSL_write() that starts a
 * nonblocking client handshake returns WANT_READ. librelp must wait for read
 * readiness, and must not retain a send retry after the handshake finishes.
 */
#include <assert.h>
#include <stdio.h>

#include "config.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "librelp.h"
#include "tcp.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

int
main(void)
{
	/* OPENSSL_init_ssl() and TLS_{client,server}_method() require OpenSSL 1.1. */
	return 77;
}

#else

static void
check_ssl(int ok, const char *what)
{
	if(!ok) {
		fprintf(stderr, "%s failed\n", what);
		ERR_print_errors_fp(stderr);
		abort();
	}
}

static void
drive_server_handshake(SSL *server)
{
	const int ret = SSL_do_handshake(server);
	if(ret != 1) {
		const int err = SSL_get_error(server, ret);
		assert(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
	}
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpTcp_t *tcp = NULL;
	SSL_CTX *client_ctx = NULL;
	SSL_CTX *server_ctx = NULL;
	SSL *server = NULL;
	BIO *client_bio = NULL;
	BIO *server_bio = NULL;
	relpOctet_t msg[] = "regression";
	ssize_t len = sizeof(msg) - 1;
	int i;

	check_ssl(OPENSSL_init_ssl(0, NULL), "OPENSSL_init_ssl");
	client_ctx = SSL_CTX_new(TLS_client_method());
	server_ctx = SSL_CTX_new(TLS_server_method());
	check_ssl(client_ctx != NULL && server_ctx != NULL, "SSL_CTX_new");
	SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
	check_ssl(SSL_CTX_load_verify_locations(client_ctx, TEST_CERT_DIR "/ossl-ca.pem", NULL),
		"SSL_CTX_load_verify_locations");
	check_ssl(SSL_CTX_use_certificate_file(server_ctx, TEST_CERT_DIR "/ossl-server-cert.pem",
		SSL_FILETYPE_PEM), "SSL_CTX_use_certificate_file");
	check_ssl(SSL_CTX_use_PrivateKey_file(server_ctx, TEST_CERT_DIR "/ossl-server-key.pem",
		SSL_FILETYPE_PEM), "SSL_CTX_use_PrivateKey_file");
	check_ssl(SSL_CTX_check_private_key(server_ctx), "SSL_CTX_check_private_key");

	assert(relpEngineConstruct(&engine) == RELP_RET_OK);
	assert(relpEngineSetDbgprint(engine, NULL) == RELP_RET_OK);
	assert(relpEngineSetTLSLib(engine, 1) == RELP_RET_OK);
	assert(relpTcpConstruct(&tcp, engine, RELP_CLT_CONN, NULL) == RELP_RET_OK);
	tcp->bEnableTLS = 1;
	tcp->bTLSActive = 1;
	tcp->sslState = osslClient;
	tcp->ssl = SSL_new(client_ctx);
	server = SSL_new(server_ctx);
	check_ssl(tcp->ssl != NULL && server != NULL, "SSL_new");
	check_ssl(BIO_new_bio_pair(&client_bio, 0, &server_bio, 0), "BIO_new_bio_pair");
	SSL_set_bio(tcp->ssl, client_bio, client_bio);
	SSL_set_bio(server, server_bio, server_bio);
	SSL_set_connect_state(tcp->ssl);
	SSL_set_accept_state(server);

	assert(relpTcpSend(tcp, msg, &len) == RELP_RET_OK);
	assert(len == 0);
	assert(relpTcpGetRtryDirection(tcp) == 0);

	for(i = 0; i < 8 && !SSL_is_init_finished(tcp->ssl); ++i) {
		drive_server_handshake(server);
		assert(relpTcpRtryHandshake(tcp) == RELP_RET_OK);
	}
	assert(SSL_is_init_finished(tcp->ssl));
	drive_server_handshake(server);
	assert(SSL_is_init_finished(server));
	assert(relpTcpGetRtryDirection(tcp) == 0);

	len = sizeof(msg) - 1;
	assert(relpTcpSend(tcp, msg, &len) == RELP_RET_OK);
	assert(len == (ssize_t) (sizeof(msg) - 1));
	assert(relpTcpGetRtryDirection(tcp) == 0);

	SSL_free(server);
	relpTcpDestruct(&tcp);
	relpEngineDestruct(&engine);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	return 0;
}

#endif
