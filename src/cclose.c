/* SPDX-License-Identifier: Apache-2.0 */

/* The command handler for "close"
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
#include "config.h"
#include <stdlib.h>
#include <assert.h>
#include "relp.h"
#include "cmdif.h"

/* as a quick hack, we provide our command handler prototypes here
 * right in front of the dispatcher. This saves us many otherwise-unneeded
 * header files (and will go away if we make them dynamically loadable).
 * alorbach, 2020-09-09
 */
/* core (protocol) commands */
PROTOTYPEcommand(S, Close)

/* process the command
 * rgerhards, 2008-03-21
 */
BEGINcommand(S, Close)
	ENTER_RELPFUNC;
	pSess->pEngine->dbgprint((char*)"in close command handler\n");

	/* and send it... */
	CHKRet(relpSessSendResponse(pSess, pFrame->txnr, (unsigned char*) "", 0));

	iRet = RELP_RET_SESSION_CLOSED; /* indicate close condition */

finalize_it:
ENDcommand
