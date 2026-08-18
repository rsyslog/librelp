/*
 * Verify accepted-socket ownership on an error after ownership transfer.
 *
 * An invalid GnuTLS priority provides a deterministic failure after
 * relpTcpAcceptConnReq() assigns the accepted socket to relpTcp_t. The close
 * wrapper reuses that descriptor after relpTcpDestruct() closes it. Error
 * cleanup must not close the replacement descriptor a second time.
 */
#include "config.h"

#if defined(ENABLE_TLS)

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "librelp.h"
#include "relpsrv.h"
#include "tcp.h"

static int watched_fd = -1;
static int replacement_fd = -1;
static int replacement_installed;
static int wrapper_error;
static unsigned int watched_close_count;

int __real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __real_close(int fd);
int __wrap_close(int fd);

int
__wrap_accept(const int sockfd, struct sockaddr *const addr, socklen_t *const addrlen)
{
	const int fd = __real_accept(sockfd, addr, addrlen);
	if(fd >= 0)
		watched_fd = fd;
	return fd;
}

int
__wrap_close(const int fd)
{
	if(fd == watched_fd) {
		++watched_close_count;
		const int ret = __real_close(fd);
		if(watched_close_count == 1 && ret == 0) {
			if(dup2(replacement_fd, watched_fd) == -1)
				wrapper_error = errno;
			else
				replacement_installed = 1;
		}
		return ret;
	}
	return __real_close(fd);
}

static void
discard_debug(char *const fmt __attribute__((unused)), ...)
{
}

static void
close_real(const int fd)
{
	if(fd >= 0)
		(void) __real_close(fd);
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpSrv_t *server = NULL;
	relpTcp_t *accepted = NULL;
	struct sockaddr_in address = {0};
	socklen_t address_len = sizeof(address);
	int replacement[2] = {-1, -1};
	int listener = -1;
	int client = -1;
	int rc = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK
	   || relpEngineSetDbgprint(engine, discard_debug) != RELP_RET_OK
	   || relpEngineSetTLSLibByName(engine, "gnutls") != RELP_RET_OK
	   || relpSrvConstruct(&server, engine) != RELP_RET_OK
	   || relpTcpConstruct(&server->pTcp, engine, RELP_SRV_CONN, server) != RELP_RET_OK
	   || relpTcpEnableTLS(server->pTcp) != RELP_RET_OK
	   || relpTcpSetGnuTLSPriString(server->pTcp, (char *) "INVALID-PRIORITY") != RELP_RET_OK) {
		fprintf(stderr, "failed to construct librelp test objects\n");
		goto done;
	}

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement) != 0) {
		perror("socketpair");
		goto done;
	}
	replacement_fd = replacement[0];

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if(listener == -1) {
		perror("socket");
		goto done;
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if(bind(listener, (struct sockaddr *) &address, sizeof(address)) != 0
	   || listen(listener, 1) != 0
	   || getsockname(listener, (struct sockaddr *) &address, &address_len) != 0) {
		perror("listener setup");
		goto done;
	}

	client = socket(AF_INET, SOCK_STREAM, 0);
	if(client == -1 || connect(client, (struct sockaddr *) &address, sizeof(address)) != 0) {
		perror("connect");
		goto done;
	}

	if(relpTcpAcceptConnReq(&accepted, listener, server) != RELP_RET_INVLD_TLS_PRIO) {
		fprintf(stderr, "accept did not fail at the expected post-transfer point\n");
		goto done;
	}
	if(accepted != NULL) {
		fprintf(stderr, "failed accept returned a connection object\n");
		goto done;
	}
	if(wrapper_error != 0) {
		errno = wrapper_error;
		perror("could not reuse accepted descriptor");
		goto done;
	}
	if(!replacement_installed || watched_close_count != 1) {
		fprintf(stderr, "accepted descriptor was closed %u times\n", watched_close_count);
		goto done;
	}

	errno = 0;
	if(fcntl(watched_fd, F_GETFD) == -1) {
		perror("replacement descriptor was closed by accept cleanup");
		goto done;
	}

	printf("replacement descriptor remained open after accept cleanup\n");
	rc = EXIT_SUCCESS;

done:
	if(accepted != NULL)
		(void) relpTcpDestruct(&accepted);
	if(server != NULL)
		(void) relpSrvDestruct(&server);
	if(engine != NULL)
		(void) relpEngineDestruct(&engine);
	close_real(watched_fd);
	close_real(client);
	close_real(listener);
	close_real(replacement[0]);
	close_real(replacement[1]);
	return rc;
}

#else

int
main(void)
{
	return 77;
}

#endif
