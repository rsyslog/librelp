/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "relp.h"
#include "relpclt.h"
#include "relpsess.h"
#include "tcp.h"

static const char *expectedAddress;
static int expectedTimeoutSeconds;
static int resolverError;
static unsigned int bindCalls;

relpRetVal __wrap_relpSessConnect(relpSess_t *session, int family, unsigned char *port, unsigned char *host,
                                 int connectTimeoutSeconds);
relpRetVal __wrap_relpSessTryReestablish(relpSess_t *session, int connectTimeoutSeconds);
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result);
int __real_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result);
int __wrap_bind(int socketFd, const struct sockaddr *address, socklen_t length);

int
__wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result)
{
	if(resolverError != 0) {
		if(resolverError == EAI_SYSTEM)
			errno = EIO;
		return resolverError;
	}
	return __real_getaddrinfo(node, service, hints, result);
}

int
__wrap_bind(int socketFd, const struct sockaddr *address, socklen_t length)
{
	++bindCalls;
	errno = socketFd == -1 && address != NULL && length == sizeof(struct sockaddr_in) && address->sa_family == AF_INET
		? EADDRNOTAVAIL : EINVAL;
	return -1;
}

/* Observe settings passed to session setup without opening a socket. */
relpRetVal
__wrap_relpSessConnect(relpSess_t LIBRELP_ATTR_UNUSED *session, int LIBRELP_ATTR_UNUSED family,
                      unsigned char LIBRELP_ATTR_UNUSED *port, unsigned char LIBRELP_ATTR_UNUSED *host,
                      int connectTimeoutSeconds)
{
	return connectTimeoutSeconds == expectedTimeoutSeconds ? RELP_RET_OK : RELP_RET_ERR_INVAL;
}
relpRetVal
__wrap_relpSessTryReestablish(relpSess_t *session, int connectTimeoutSeconds)
{
	const relpSourceBind_t *const binding = &session->sourceBind;
	struct sockaddr_in actual;
	struct in_addr expected;

	if(connectTimeoutSeconds != expectedTimeoutSeconds) {
		fprintf(stderr, "reconnect timeout was %d seconds, expected %d\n",
			connectTimeoutSeconds, expectedTimeoutSeconds);
		return RELP_RET_ERR_INVAL;
	}
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
	unsigned char port[] = "20514";
	unsigned char host[] = "127.0.0.1";
	unsigned char initialAddress[] = "127.0.0.2";
	unsigned char changedAddress[] = "127.0.0.3";
	const struct {
		int resolverError;
		relpRetVal expected;
	} resolutionErrors[] = {
		{EAI_NONAME, RELP_RET_ERR_INVAL},
		{EAI_AGAIN, RELP_RET_IO_ERR},
		{EAI_SYSTEM, RELP_RET_IO_ERR},
		{EAI_MEMORY, RELP_RET_OUT_OF_MEMORY}
	};
	int result = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK ||
	   relpEngineSetDbgprint(engine, NULL) != RELP_RET_OK ||
	   relpCltConstruct(&client, engine) != RELP_RET_OK ||
	   relpCltSetClientIP(client, initialAddress) != RELP_RET_OK)
		goto done;

	expectedTimeoutSeconds = RELP_DFLT_CONN_TIMEOUT;
	if(relpCltConnect(client, AF_INET, port, host) != RELP_RET_OK ||
	   relpCltSetConnTimeout(client, 15) != RELP_RET_OK) {
		fprintf(stderr, "initial connection did not use the default timeout or setting the override failed\n");
		goto done;
	}
	expectedAddress = (const char *)changedAddress;
	if(relpCltSetClientIP(client, changedAddress) != RELP_RET_OK ||
	   relpCltReconnect(client) != RELP_RET_OK) {
		fprintf(stderr, "reconnect did not use the changed source address\n");
		goto done;
	}

	for(size_t i = 0; i < sizeof(resolutionErrors) / sizeof(resolutionErrors[0]); ++i) {
		resolverError = resolutionErrors[i].resolverError;
		if(relpCltSetClientIP(client, initialAddress) != resolutionErrors[i].expected ||
		   relpCltReconnect(client) != RELP_RET_OK) {
			fprintf(stderr, "incorrect result or lost binding after resolver error %d\n", resolverError);
			goto done;
		}
	}
	resolverError = 0;

	if(relpSourceBindApply(&client->sourceBind, -1, AF_INET) != EADDRNOTAVAIL ||
	   relpSourceBindApply(&client->sourceBind, -1, AF_INET6) != EAFNOSUPPORT ||
	   bindCalls != 1) {
		fprintf(stderr, "source binding did not preserve the bind error\n");
		goto done;
	}

	expectedAddress = NULL;
	if(relpCltSetClientIP(client, NULL) != RELP_RET_OK ||
	   relpCltReconnect(client) != RELP_RET_OK ||
	   relpSourceBindApply(&client->sourceBind, -1, AF_INET) != 0 || bindCalls != 1) {
		fprintf(stderr, "reconnect retained the cleared source address\n");
		goto done;
	}
	expectedTimeoutSeconds = 15;
	if(relpSessDestruct(&client->pSess) != RELP_RET_OK ||
	   relpCltConnect(client, AF_INET, port, host) != RELP_RET_OK) {
		fprintf(stderr, "fresh connection did not use the new timeout\n");
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
