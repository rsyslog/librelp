/* SPDX-License-Identifier: Apache-2.0 */

/* The command handler for "serverclose" hint.
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
PROTOTYPEcommand(C, Serverclose)

/* process the command
 * Note: this is a hint, so we do not (and MUST NOT) send a response.
 * rgerhards, 2008-03-31
 */
BEGINcommand(C, Serverclose)
	ENTER_RELPFUNC;
	pSess->pEngine->dbgprint((char*)"in serverclose command handler\n");

	/* We use state "broken" so that our usual recovery can kick in */
	relpSessSetSessState(pSess, eRelpSessState_BROKEN);
	iRet = RELP_RET_SESSION_CLOSED; /* indicate close condition */
ENDcommand
