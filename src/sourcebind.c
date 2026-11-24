/* SPDX-License-Identifier: Apache-2.0 */

#include "config.h"
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
		if(result != 0)
			return result == EAI_MEMORY ? RELP_RET_OUT_OF_MEMORY : RELP_RET_ERR_INVAL;

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

const struct addrinfo *
relpSourceBindSelect(const relpSourceBind_t *binding, const struct addrinfo *destinations,
	const relpSourceEndpoint_t **source)
{
	*source = NULL;
	if(binding->ipv4.length == 0 && binding->ipv6.length == 0)
		return destinations;

	for(const struct addrinfo *dest = destinations; dest != NULL; dest = dest->ai_next) {
		if(dest->ai_family == AF_INET && binding->ipv4.length != 0) {
			*source = &binding->ipv4;
			return dest;
		}
		if(dest->ai_family == AF_INET6 && binding->ipv6.length != 0) {
			*source = &binding->ipv6;
			return dest;
		}
	}
	return NULL;
}
