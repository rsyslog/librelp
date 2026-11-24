/* SPDX-License-Identifier: Apache-2.0 */

/* The command handler for server-based "syslog" (after reception)
 *
 * This command is used to transfer syslog messages.
 *
 * Copyright 2008-2025 by Rainer Gerhards and Adiscon GmbH.
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
PROTOTYPEcommand(S, Syslog)

/* process the command
 * rgerhards, 2008-03-17
 */
BEGINcommand(S, Syslog)
	ENTER_RELPFUNC;
	pSess->pEngine->dbgprint((char*)"in 'syslog' command handler\n");

	if(pSess->stateCmdSyslog != eRelpCmdState_Enabled) {
		relpSessSendResponse(pSess, pFrame->txnr, (unsigned char*) "500 command disabled", 20);
		ABORT_FINALIZE(RELP_RET_CMD_DISABLED);
	}

	/* TODO: right now, the callbacks are called without checking the
	 * return code. I assume this should at least be optionally done.
	 * Consider implementing this. rgerhards, 2018-04-17
	 */
       /* only highest version callback is called */
       if(pSess->pEngine->onSyslogRcv3 != NULL) {
               pSess->pEngine->onSyslogRcv3(pSess->pSrv->pUsr, pSess->pTcp->pRemHostName,
                                               pSess->pTcp->pRemHostIP, pSess->pTcp->pRemHostPort,
                                               pFrame->pData, pFrame->lenData);
       } else if(pSess->pEngine->onSyslogRcv2 != NULL) {
               pSess->pEngine->onSyslogRcv2(pSess->pSrv->pUsr, pSess->pTcp->pRemHostName,
                                               pSess->pTcp->pRemHostIP, pFrame->pData, pFrame->lenData);
       } else if(pSess->pEngine->onSyslogRcv != NULL) {
               pSess->pEngine->onSyslogRcv(pSess->pTcp->pRemHostName, pSess->pTcp->pRemHostIP,
                                               pFrame->pData, pFrame->lenData);
       } else {
               pSess->pEngine->dbgprint((char*)"error: no syslog reception callback is set, nothing done\n");
       }

	/* send response */
	iRet = relpSessSendResponse(pSess, pFrame->txnr, (unsigned char*) "200 OK", 6);
finalize_it:
ENDcommand
