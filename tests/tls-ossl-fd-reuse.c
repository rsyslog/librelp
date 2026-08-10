/*
 * Deterministic reproducer for OpenSSL BIO socket ownership.
 *
 * librelp closes pTcp->sock before freeing its SSL object. The callback below
 * reuses the descriptor between those two operations. The SSL socket BIO must
 * not close the replacement descriptor when SSL_free() destroys the BIO.
 */
#include "config.h"

#if defined(ENABLE_TLS_OPENSSL)

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#include "librelp.h"
#include "tcp.h"

static int watched_fd = -1;
static int replacement_fd = -1;
static int replacement_installed;
static int callback_error;

static void
discard_debug(char *const fmt __attribute__((unused)), ...)
{
}

static long
reuse_closed_fd(BIO *const bio __attribute__((unused)), const int operation,
	const char *const argp __attribute__((unused)),
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	const size_t len __attribute__((unused)),
#endif
	const int argi __attribute__((unused)), const long argl __attribute__((unused)),
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	const int ret, size_t *const processed __attribute__((unused)))
#else
	const long ret)
#endif
{
	if((operation & ~BIO_CB_RETURN) == BIO_CB_FREE && !replacement_installed) {
		errno = 0;
		if(fcntl(watched_fd, F_GETFD) == -1 && errno == EBADF) {
			if(dup2(replacement_fd, watched_fd) == -1)
				callback_error = errno;
			else
				replacement_installed = 1;
		}
	}

	return ret;
}

static void
close_if_open(const int fd)
{
	if(fd >= 0)
		(void) close(fd);
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpTcp_t *tcp = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	BIO *bio = NULL;
	int connection[2] = {-1, -1};
	int replacement[2] = {-1, -1};
	int rc = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK
	   || relpEngineSetDbgprint(engine, discard_debug) != RELP_RET_OK
	   || relpEngineSetTLSLibByName(engine, "openssl") != RELP_RET_OK
	   || relpTcpConstruct(&tcp, engine, RELP_CLT_CONN, NULL) != RELP_RET_OK) {
		fprintf(stderr, "failed to construct librelp test objects\n");
		goto done;
	}

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement) != 0
	   || socketpair(AF_UNIX, SOCK_STREAM, 0, connection) != 0) {
		perror("socketpair");
		goto done;
	}

	if(!SSL_library_init()) {
		fprintf(stderr, "failed to initialize OpenSSL\n");
		goto done;
	}

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	ssl = ssl_ctx == NULL ? NULL : SSL_new(ssl_ctx);
	if(ssl == NULL) {
		fprintf(stderr, "failed to construct OpenSSL test objects\n");
		goto done;
	}

	tcp->sock = connection[0];
	connection[0] = -1; /* tcp owns this descriptor from here on */
	tcp->ssl = ssl;
	ssl = NULL; /* tcp owns the SSL object from here on */
	tcp->bTLSActive = 1;
	tcp->sslState = osslClient;

	bio = relpTcpNewSocketBio_ossl(tcp->sock);
	if(bio == NULL) {
		fprintf(stderr, "failed to construct OpenSSL socket BIO\n");
		goto done;
	}
	SSL_set_bio(tcp->ssl, bio, bio);
	SSL_set_connect_state(tcp->ssl);
	SSL_set_shutdown(tcp->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

	watched_fd = tcp->sock;
	replacement_fd = replacement[0];
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	BIO_set_callback_ex(bio, reuse_closed_fd);
#else
	BIO_set_callback(bio, reuse_closed_fd);
#endif

	if(relpTcpDestruct(&tcp) != RELP_RET_OK) {
		fprintf(stderr, "relpTcpDestruct failed\n");
		goto done;
	}

	if(callback_error != 0) {
		errno = callback_error;
		perror("could not reuse manually closed descriptor");
		goto done;
	}
	if(!replacement_installed) {
		fprintf(stderr, "descriptor was not reusable before BIO destruction\n");
		goto done;
	}

	errno = 0;
	if(fcntl(watched_fd, F_GETFD) == -1 && errno == EBADF) {
		fprintf(stderr, "SSL_free closed a descriptor reused after librelp's manual close\n");
		goto done;
	}

	printf("replacement descriptor remained open after SSL destruction\n");
	rc = EXIT_SUCCESS;

done:
	if(tcp != NULL)
		(void) relpTcpDestruct(&tcp);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);
	if(engine != NULL)
		(void) relpEngineDestruct(&engine);
	close_if_open(watched_fd);
	close_if_open(connection[0]);
	close_if_open(connection[1]);
	close_if_open(replacement[0]);
	close_if_open(replacement[1]);
	return rc;
}

#else

int
main(void)
{
	return 77;
}

#endif
