/* A disconnected peer must produce an I/O error, not terminate the process. */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "librelp.h"
#include "tcp.h"

static void
discard_debug(char *const fmt __attribute__((unused)), ...)
{
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpTcp_t *tcp = NULL;
	int sockets[2] = {-1, -1};
	relpOctet_t message[] = "test";
	ssize_t length = sizeof(message) - 1;
	int rc = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK
	   || relpEngineSetDbgprint(engine, discard_debug) != RELP_RET_OK
	   || relpTcpConstruct(&tcp, engine, RELP_CLT_CONN, NULL) != RELP_RET_OK
	   || socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
		fprintf(stderr, "could not construct plaintext send test\n");
		goto done;
	}

	tcp->sock = sockets[0];
	sockets[0] = -1;
	close(sockets[1]);
	sockets[1] = -1;
	if(relpTcpSend(tcp, message, &length) != RELP_RET_IO_ERR) {
		fprintf(stderr, "send to a closed peer did not return an I/O error\n");
		goto done;
	}
	rc = EXIT_SUCCESS;

done:
	if(tcp != NULL)
		(void) relpTcpDestruct(&tcp);
	if(engine != NULL)
		(void) relpEngineDestruct(&engine);
	if(sockets[0] != -1)
		close(sockets[0]);
	if(sockets[1] != -1)
		close(sockets[1]);
	return rc;
}
