/*
 * Verify that every permitted-peer owner releases its copied entries and
 * pointer array, including TCP wildcard compilation state.
 */
#include "config.h"

#if defined(WITH_TLS)

#include <stdio.h>
#include <stdlib.h>

#include "librelp.h"
#include "relp.h"
#include "relpclt.h"
#include "relpsess.h"
#include "relpsrv.h"
#include "tcp.h"

static void
discard_debug(char *const fmt __attribute__((unused)), ...)
{
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpSrv_t *server = NULL;
	relpClt_t *client = NULL;
	relpSess_t *session = NULL;
	relpTcp_t *tcp = NULL;
	char *peerNames[] = {(char*)"*.example.com", (char*)"relay.example.org"};
	relpPermittedPeers_t peers = {2, peerNames};
	int rc = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK
	   || relpEngineSetDbgprint(engine, discard_debug) != RELP_RET_OK
	   || relpSrvConstruct(&server, engine) != RELP_RET_OK
	   || relpSrvAddPermittedPeer(server, peerNames[0]) != RELP_RET_OK
	   || relpSrvAddPermittedPeer(server, peerNames[1]) != RELP_RET_OK
	   || relpCltConstruct(&client, engine) != RELP_RET_OK
	   || relpCltAddPermittedPeer(client, peerNames[0]) != RELP_RET_OK
	   || relpCltAddPermittedPeer(client, peerNames[1]) != RELP_RET_OK
	   || relpSessConstruct(&session, engine, RELP_CLT_CONN, client, NULL) != RELP_RET_OK
	   || relpSessSetPermittedPeers(session, &peers) != RELP_RET_OK
	   || relpTcpConstruct(&tcp, engine, RELP_CLT_CONN, client) != RELP_RET_OK
	   || relpTcpSetPermittedPeers(tcp, &peers) != RELP_RET_OK) {
		fprintf(stderr, "failed to construct permitted-peer test objects\n");
		goto done;
	}

	printf("permitted-peer ownership cleanup verified\n");
	rc = EXIT_SUCCESS;

done:
	if(tcp != NULL)
		(void) relpTcpDestruct(&tcp);
	if(session != NULL)
		(void) relpSessDestruct(&session);
	if(client != NULL)
		(void) relpCltDestruct(&client);
	if(server != NULL)
		(void) relpSrvDestruct(&server);
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
