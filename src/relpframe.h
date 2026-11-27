/* SPDX-License-Identifier: Apache-2.0 */

/* The RELPFRAME object.
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
#ifndef RELPFRAME_H_INCLUDED
#define	RELPFRAME_H_INCLUDED


/* state the relpframe may have during reception of messages */
typedef enum relpFrameRcvStates_e {
	eRelpFrameRcvState_BEGIN_FRAME = 0,
	eRelpFrameRcvState_IN_TXNR = 1,
	eRelpFrameRcvState_IN_CMD = 2,
	eRelpFrameRcvState_IN_DATALEN = 3,
	eRelpFrameRcvState_IN_DATA = 4,
	eRelpFrameRcvState_IN_TRAILER = 5,
	eRelpFrameRcvState_FINISHED = 6	 /**< the frame is fully received and ready for processing */
} relpFrameRcvState_t;


/* the RELPFRAME object
 * rgerhards, 2008-03-16
 */
struct relpFrame_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	relpFrameRcvState_t rcvState;
	size_t iRcv;		/**< a multi-purpose field index used during frame reception */
	relpTxnr_t txnr;	/**< the current transaction (sequence) number */
	relpOctet_t cmd[32+1];	/**< the current command (+1 for C string terminator) */
	size_t lenData;		/**< length of data part of frame */
	relpOctet_t *pData;	/**< frame data part */
	size_t idxData;		/**< keeps track of processed chars when reading pData bytewise */
};

#include "relpsess.h" /* this needs to be done after relpFrame_t is defined! */
#include "sendbuf.h"

/* prototypes */
relpRetVal relpFrameProcessOctetRcvd(relpFrame_t **ppThis, relpOctet_t c, relpSess_t *pSess);
void relpFrameDiscardPendingReceive(relpSess_t *pSess);
relpRetVal relpFrameBuildSendbuf(relpSendbuf_t **ppSendbuf, relpTxnr_t txnr, unsigned char *pCmd, size_t lenCmd,
	   relpOctet_t *pData, size_t lenData, relpSess_t *pSess, relpRetVal (*rspHdlr)(relpSess_t*,relpFrame_t*));
relpRetVal relpFrameRewriteTxnr(relpSendbuf_t *pSendbuf, relpTxnr_t txnr);
relpRetVal relpFrameGetNextC(relpFrame_t *pThis, unsigned char *pC);

#endif /* #ifndef RELPFRAME_H_INCLUDED */
