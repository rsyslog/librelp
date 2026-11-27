/* SPDX-License-Identifier: Apache-2.0 */

/* The RELPSRV object.
 *
 * Copyright 2008-2013 by Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 *
 * ALL CONTRIBUTORS PLEASE NOTE that by sending contributions, you assign
 * your copyright to Adiscon GmbH, Germany.
 */
#ifndef RELPSRV_H_INCLUDED
#define	RELPSRV_H_INCLUDED

#include <stdbool.h>

#include "relp.h"
#include "tcp.h"

/* the RELPSRV object
 * rgerhards, 2008-03-17
 */
struct relpSrv_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	unsigned char *pLstnPort;
	unsigned char *bindNode; /**< optional hostname or numeric bind address */
	int ai_family;
	relpTcp_t *pTcp; /**< our tcp support object */
	struct {
		size_t bytes;
		bool configured;
	} receiveLimit;
	int oversizeMode;
	void *pUsr; /**< user pointer (passed back in to callback) */
	int bKeepAlive;			/* support keep-alive packets */
	int iKeepAliveIntvl;
	int iKeepAliveProbes;
	int iKeepAliveTime;
	int bEnableTLS;			/* support for TLS */
	int bEnableTLSZip;
	int dhBits;	/**< number of bits for Diffie-Hellman key */
	char *pristring; /**< priority string for GnuTLS */
	char *caCertFile;
	char *ownCertFile;
	char *privKey;
	char *tlsConfigCmd;	/**< optional configuration command property for TLS libs **/
	relpAuthMode_t authmode;
	relpPermittedPeers_t permittedPeers;

	/* Status of commands as supported in this session. */
	relpCmdEnaState_t stateCmdSyslog;
};


/* macros for quick memeber access */
#define relpSrvGetNumLstnSocks(pThis) (relpTcpGetNumSocks((pThis)->pTcp))
#define relpSrvGetLstnSock(pThis, i)  (relpTcpGetLstnSock((pThis)->pTcp, i))

/* prototypes */
relpRetVal relpSrvConstruct(relpSrv_t **ppThis, relpEngine_t *pEngine);
relpRetVal relpSrvDestruct(relpSrv_t **ppThis);
relpRetVal relpSrvSetFamily(relpSrv_t *pThis, int ai_family);
relpRetVal relpSrvRun(relpSrv_t *pThis);
size_t relpSrvGetReceiveLimit(const relpSrv_t *pThis);

#endif /* #ifndef RELPSRV_H_INCLUDED */
