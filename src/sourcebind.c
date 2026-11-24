/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include "sourcebind.h"

relpRetVal
relpSourceBindResolve(relpSourceBind_t *binding, const char *address)
{
	relpSourceBind_t next;
	memset(&next, 0, sizeof(next));
	if(address != NULL) {
		const struct addrinfo hints = {
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM
		};
		struct addrinfo *resolved;
		const int result = getaddrinfo(address, "0", &hints, &resolved);
		if(result != 0) {
			if(result == EAI_MEMORY)
				return RELP_RET_OUT_OF_MEMORY;
			if(result == EAI_AGAIN || result == EAI_SYSTEM)
				return RELP_RET_IO_ERR;
			return RELP_RET_ERR_INVAL;
		}

		for(const struct addrinfo *entry = resolved; entry != NULL; entry = entry->ai_next) {
			relpSourceEndpoint_t *endpoint;
			switch(entry->ai_family) {
			case AF_INET:
				endpoint = &next.ipv4;
				break;
			case AF_INET6:
				endpoint = &next.ipv6;
				break;
			default:
				continue;
			}
			if(endpoint->length == 0 && entry->ai_addrlen <= sizeof(endpoint->address)) {
				memcpy(&endpoint->address, entry->ai_addr, entry->ai_addrlen);
				endpoint->length = entry->ai_addrlen;
			}
		}
		freeaddrinfo(resolved);
		if(next.ipv4.length == 0 && next.ipv6.length == 0)
			return RELP_RET_ERR_INVAL;
	}
	*binding = next;
	return RELP_RET_OK;
}

static const relpSourceEndpoint_t *
sourceForFamily(const relpSourceBind_t *binding, int family)
{
	if(family == AF_INET && binding->ipv4.length != 0)
		return &binding->ipv4;
	if(family == AF_INET6 && binding->ipv6.length != 0)
		return &binding->ipv6;
	return NULL;
}

int
relpSourceBindAllowsFamily(const relpSourceBind_t *binding, int family)
{
	return (binding->ipv4.length == 0 && binding->ipv6.length == 0) ||
		sourceForFamily(binding, family) != NULL;
}

int
relpSourceBindApply(const relpSourceBind_t *binding, int socketFd, int family)
{
	if(binding->ipv4.length == 0 && binding->ipv6.length == 0)
		return 0;

	const relpSourceEndpoint_t *const source = sourceForFamily(binding, family);
	if(source == NULL)
		return EAFNOSUPPORT;
	if(bind(socketFd, (const struct sockaddr *)&source->address, source->length) != 0)
		return errno;
	return 0;
}
