/* SPDX-License-Identifier: Apache-2.0 */

/* This header defines the interface between the relp engine
 * and relp commands. A consistent interface is used to dispatch
 * commands to the respective command handlers. All handlers shall
 * use the macros provided in this file. This is especially important
 * as the interface may evolve in the future and the macros most
 * probably will hide the details.
 *
 * Please note that for each command there is a server- and a client
 * based handler. They, as well as all commands, are provided in separate
 * source files so that we can get to a nice granularity inside our
 * library (just in case if a resource-constrained caller needs to pull
 * just the bare essentials into its binary).
 *
 * Copyright 2008 by Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 *
 * ALL CONTRIBUTORS PLEASE NOTE that by sending contributions, you assign
 * your copyright to Adiscon GmbH, Germany.
 */
#ifndef RELP_CMDIF_H_INCLUDED
#define	RELP_CMDIF_H_INCLUDED

#include "relpframe.h"

#define PROTOTYPEcommand(type, cmd) \
	relpRetVal relp##type##C##cmd(relpFrame_t *pFrame, relpSess_t *pSess);

#define BEGINcommand(type, cmd) \
	relpRetVal relp##type##C##cmd(relpFrame_t LIBRELP_ATTR_UNUSED *pFrame, relpSess_t *pSess) \
	{ \
		RELPOBJ_assert(pFrame, Frame); \
		RELPOBJ_assert(pSess, Sess);

#define ENDcommand \
		LEAVE_RELPFUNC; \
	}


#endif /* #ifndef RELP_CMDIF_H_INCLUDED */
