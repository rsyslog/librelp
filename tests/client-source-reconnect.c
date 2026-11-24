/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "relp.h"
#include "relpclt.h"
#include "relpsess.h"
#include "tcp.h"

static const char *expectedAddress;

relpRetVal __wrap_relpSessTryReestablish(relpSess_t *session);

/* Observe the binding given to the reconnect path without opening a socket. */
relpRetVal
__wrap_relpSessTryReestablish(relpSess_t *session)
{
	const relpSourceBind_t *const binding = &session->sourceBind;
	struct sockaddr_in actual;
	struct in_addr expected;

	if(expectedAddress == NULL)
		return binding->ipv4.length == 0 && binding->ipv6.length == 0
			? RELP_RET_OK : RELP_RET_ERR_INVAL;

	if(binding->ipv4.length != sizeof(actual) || binding->ipv6.length != 0 ||
	   inet_pton(AF_INET, expectedAddress, &expected) != 1)
		return RELP_RET_ERR_INVAL;

	memcpy(&actual, &binding->ipv4.address, sizeof(actual));
	return actual.sin_family == AF_INET && actual.sin_addr.s_addr == expected.s_addr
		? RELP_RET_OK : RELP_RET_ERR_INVAL;
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpClt_t *client = NULL;
	unsigned char initialAddress[] = "127.0.0.2";
	unsigned char changedAddress[] = "127.0.0.3";
	unsigned char invalidAddress[] = "invalid:ipv6:address";
	int result = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK ||
	   relpEngineSetDbgprint(engine, NULL) != RELP_RET_OK ||
	   relpCltConstruct(&client, engine) != RELP_RET_OK ||
	   relpSessConstruct(&client->pSess, engine, RELP_CLT_CONN, client, NULL) != RELP_RET_OK ||
	   relpCltSetClientIP(client, initialAddress) != RELP_RET_OK)
		goto done;

	/* Start with the binding that an earlier successful connect captured. */
	client->pSess->sourceBind = client->sourceBind;
	expectedAddress = (const char *)changedAddress;
	if(relpCltSetClientIP(client, changedAddress) != RELP_RET_OK ||
	   relpCltReconnect(client) != RELP_RET_OK) {
		fprintf(stderr, "reconnect did not use the changed source address\n");
		goto done;
	}

	if(relpCltSetClientIP(client, invalidAddress) == RELP_RET_OK ||
	   relpCltReconnect(client) != RELP_RET_OK) {
		fprintf(stderr, "a failed update did not preserve the source address\n");
		goto done;
	}

	expectedAddress = NULL;
	if(relpCltSetClientIP(client, NULL) != RELP_RET_OK ||
	   relpCltReconnect(client) != RELP_RET_OK) {
		fprintf(stderr, "reconnect retained the cleared source address\n");
		goto done;
	}
	result = EXIT_SUCCESS;

done:
	if(client != NULL)
		(void)relpCltDestruct(&client);
	if(engine != NULL)
		(void)relpEngineDestruct(&engine);
	return result;
}
