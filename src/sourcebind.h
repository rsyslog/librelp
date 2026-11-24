/* SPDX-License-Identifier: Apache-2.0 */

#ifndef RELP_SOURCEBIND_H_INCLUDED
#define RELP_SOURCEBIND_H_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>
#include "librelp.h"

typedef struct {
	struct sockaddr_storage address;
	socklen_t length;
} relpSourceEndpoint_t;

typedef struct {
	relpSourceEndpoint_t ipv4;
	relpSourceEndpoint_t ipv6;
} relpSourceBind_t;

relpRetVal relpSourceBindResolve(relpSourceBind_t *binding, const char *address);
int relpSourceBindAllowsFamily(const relpSourceBind_t *binding, int family);
relpRetVal relpSourceBindApply(const relpSourceBind_t *binding, int socketFd, int family);

#endif
