/* SPDX-License-Identifier: Apache-2.0 */

/* The command handler for the "rsp" command (done at the client).
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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "librelp.h"
#include "relp.h"
#include "cmdif.h"

/* as a quick hack, we provide our command handler prototypes here
 * right in front of the dispatcher. This saves us many otherwise-unneeded
 * header files (and will go away if we make them dynamically loadable).
 * alorbach, 2020-09-09
 */
/* core (protocol) commands */
PROTOTYPEcommand(S, Rsp)

/* read the response header. The frame's pData read pointer is moved to the
 * first byte of the response data buffer (if any).
 * rgerhards, 2008-03-24
 */
static relpRetVal
readRspHdr(relpFrame_t *pFrame, int *pCode, unsigned char *pText)
{
	int iText;
	unsigned char c;
	relpRetVal localRet;

	ENTER_RELPFUNC;

	/* code - it must be exactly three digits */
	CHKRet(relpFrameGetNextC(pFrame, &c));
	if(isdigit(c)) *pCode = c - '0'; else ABORT_FINALIZE(RELP_RET_INVALID_RSPHDR);
	CHKRet(relpFrameGetNextC(pFrame, &c));
	if(isdigit(c)) *pCode = *pCode * 10 + c - '0'; else ABORT_FINALIZE(RELP_RET_INVALID_RSPHDR);
	CHKRet(relpFrameGetNextC(pFrame, &c));
	if(isdigit(c)) *pCode = *pCode * 10 + c - '0'; else ABORT_FINALIZE(RELP_RET_INVALID_RSPHDR);

	CHKRet(relpFrameGetNextC(pFrame, &c));
	if(c != ' ') ABORT_FINALIZE(RELP_RET_INVALID_RSPHDR);

	/* now come the message. It is terminated after 80 chars or when an LF
	 * is found (the LF is the delemiter to response data) or there is no
	 * more data.
	 */
	for(iText = 0 ; iText < 80 ; ++iText) {
		localRet = relpFrameGetNextC(pFrame, &c);
		if(localRet == RELP_RET_END_OF_DATA)
			break;
		else if(localRet != RELP_RET_OK)
			ABORT_FINALIZE(localRet);
		if(c == '\n')
			break;
		/* we got a regular char which we need to copy */
		pText[iText] = c;
	}
	pText[iText] = '\0'; /* make it a C-string */

finalize_it:
	LEAVE_RELPFUNC;
}


/* process a response
 * rgerhards, 2008-03-17
 */
BEGINcommand(S, Rsp)
	relpSendbuf_t *pSendbuf;
	unsigned char bufText[81]; /* max 80 chars as of RELP spec! */
	int rspCode;

	ENTER_RELPFUNC;
	CHKRet(readRspHdr(pFrame, &rspCode, bufText));
	pSess->pEngine->dbgprint((char*)"in rsp command handler, txnr %d, code %d, text '%s'\n",
				 pFrame->txnr, rspCode, bufText);
	CHKRet(relpSessGetUnacked(pSess, &pSendbuf, pFrame->txnr));

	if(rspCode == 200) {
		if(pSendbuf->rspHdlr != NULL) {
			CHKRet(pSendbuf->rspHdlr(pSess, pFrame));
		}
		CHKRet(relpSendbufDestruct(&pSendbuf));
	} else {
		if(pSess->pEngine->onErr != NULL) {
			pSess->pEngine->onErr(pSess->pUsr, (char*)"rsp command",
				(char*)"peer sent error response", RELP_RET_RSP_STATE_ERR);
		}
		iRet = RELP_RET_RSP_STATE_ERR;
		/* TODO: add a hock to a logger function of the caller */
		relpSendbufDestruct(&pSendbuf); /* don't set error code */
	}

finalize_it:
ENDcommand
