/* SPDX-License-Identifier: Apache-2.0 */

/* The RELPSENDQ object.
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
#ifndef RELPSENDQ_H_INCLUDED
#define	RELPSENDQ_H_INCLUDED

#include <pthread.h>
#include "sendbuf.h"

/* The relp sendq entry object.
 * This is a doubly-linked list
 * rgerhards, 2008-03-16
 */
typedef struct relpSendqe_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	struct relpSendqe_s *pNext;
	struct relpSendqe_s *pPrev;
	relpSendbuf_t *pBuf; /* our send buffer */
} relpSendqe_t;

/* the RELPSENDQ object
 * This provides more or less just the root of the sendq entries.
 * rgerhards, 2008-03-16
 */
typedef struct relpSendq_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	relpSendqe_t *pRoot;
	relpSendqe_t *pLast;
	pthread_mutex_t mut;
} relpSendq_t;


/* prototypes */
relpRetVal relpSendqConstruct(relpSendq_t **ppThis, relpEngine_t *pEngine);
relpRetVal relpSendqDestruct(relpSendq_t **ppThis);
relpRetVal relpSendqAddBuf(relpSendq_t *pThis, relpSendbuf_t *pBuf, relpTcp_t *pTcp);
relpRetVal relpSendqSend(relpSendq_t *pThis, relpTcp_t *pTcp);
int relpSendqIsEmpty(relpSendq_t *pThis);

#endif /* #ifndef RELPSENDQ_H_INCLUDED */
