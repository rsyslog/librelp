/* SPDX-License-Identifier: Apache-2.0 */

/* Local source address binding for RELP client connections (interface).
 *
 * Copyright 2026 by Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 */
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
/* Returns zero on success or an errno value on failure. */
int relpSourceBindApply(const relpSourceBind_t *binding, int socketFd, int family);

#endif
