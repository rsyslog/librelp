/* SPDX-License-Identifier: Apache-2.0 */

/* The RELPSENDBUF object.
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
#ifndef RELPSENDBUF_H_INCLUDED
#define	RELPSENDBUF_H_INCLUDED

#include "relpsess.h"

/* the RELPSENDBUF object
 * rgerhards, 2008-03-16
 */
struct relpSendbuf_s {
	BEGIN_RELP_OBJ;
	relpSess_t *pSess; /**< the session this buffer belongs to */
	relpOctet_t *pData; /**< the buffer, as it can be put on the wire */
	relpTxnr_t txnr; /**< our txnr in native form */
	relpRetVal (*rspHdlr)(relpSess_t*, relpFrame_t*); /**< callback when response arrived */
	size_t lenData;
	size_t lenTxnr;	/**< length of txnr - actual send buffer starts at offset (9 - lenTxnr)! */
	size_t bufPtr; /**< multi-purpose, tracks sent octets when multi-send
	 	            send() calls are required and tracks consumption of response
			    buffer in a rsp frame. */
};


/* prototypes */
relpRetVal relpSendbufConstruct(relpSendbuf_t **ppThis, relpSess_t *pSess);
relpRetVal relpSendbufDestruct(relpSendbuf_t **ppThis);
relpRetVal relpSendbufSend(relpSendbuf_t *pThis, relpTcp_t *pTcp);
relpRetVal relpSendbufSendAll(relpSendbuf_t *pThis, relpSess_t *pSess, int bAddToUnacked);
relpRetVal relpSendbufSetData(relpSendbuf_t *pThis, relpOctet_t *pData, size_t lenData);

#endif /* #ifndef RELPSENDBUF_H_INCLUDED */
