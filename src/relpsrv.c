/* SPDX-License-Identifier: Apache-2.0 */

/* The relp server.
 *
 * Copyright 2008-2018 by Rainer Gerhards and Adiscon GmbH.
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
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include "relp.h"
#include "relpsrv.h"
#include "tcp.h"

#define RELP_STRINGIFY_INNER(value) #value
#define RELP_STRINGIFY(value) RELP_STRINGIFY_INNER(value)



/** Construct a RELP srv instance
 * This is the first thing that a caller must do before calling any
 * RELP function. The relp srv must only destructed after all RELP
 * operations have been finished.
 */
relpRetVal
relpSrvConstruct(relpSrv_t **ppThis, relpEngine_t *pEngine)
{
	relpSrv_t *pThis;

	ENTER_RELPFUNC;
	assert(ppThis != NULL);
	if((pThis = malloc(sizeof(*pThis))) == NULL) {
		ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}

	*pThis = (relpSrv_t) {
		.pEngine = pEngine,
		.stateCmdSyslog = pEngine->stateCmdSyslog,
		.ai_family = AF_UNSPEC,
		.dhBits = DEFAULT_DH_BITS,
		.authmode = eRelpAuthMode_None,
		.oversizeMode = RELP_DFLT_OVERSIZE_MODE
	};
	RELP_CORE_CONSTRUCTOR(pThis, Srv);

	*ppThis = pThis;

finalize_it:
	LEAVE_RELPFUNC;
}


/** Destruct a RELP srv instance
 */
relpRetVal
relpSrvDestruct(relpSrv_t **ppThis)
{
	relpSrv_t *pThis;
	int i;

	ENTER_RELPFUNC;
	assert(ppThis != NULL);
	pThis = *ppThis;
	RELPOBJ_assert(pThis, Srv);

	if(pThis->pTcp != NULL)
		relpTcpDestruct(&pThis->pTcp);

	free(pThis->pLstnPort);
	free(pThis->bindNode);
	free(pThis->pristring);
	free(pThis->caCertFile);
	free(pThis->ownCertFile);
	free(pThis->privKey);
	free(pThis->tlsConfigCmd);
	for(i = 0 ; i < pThis->permittedPeers.nmemb ; ++i)
		free(pThis->permittedPeers.name[i]);
	free(pThis->permittedPeers.name);
	pThis->permittedPeers.name = NULL;
	pThis->permittedPeers.nmemb = 0;
	/* done with de-init work, now free srv object itself */
	free(pThis);
	*ppThis = NULL;

	LEAVE_RELPFUNC;
}


/** add a permitted peer to the current server object. As soon as the
 * first permitted peer is set, anonymous access is no longer permitted.
 * Note that currently once-set peers can never be removed. This is
 * considered to be of no importance. We assume all peers are know
 * at time of server construction. For the same reason, we do not guard
 * the update operation. It is forbidden to add peers after the server
 * has been started. In that case, races can happen.
 * rgerhards, 2013-06-18
 */
PART_OF_API relpRetVal
relpSrvAddPermittedPeer(relpSrv_t *const pThis, char *peer)
{
	char **newName;
	int newMemb;
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	newMemb = pThis->permittedPeers.nmemb + 1;
	newName = realloc(pThis->permittedPeers.name, sizeof(char*) * newMemb);
	if(newName == NULL) {
		ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
	pThis->permittedPeers.name = newName;
	if((newName[newMemb - 1] = strdup(peer)) == NULL) {
		ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
	pThis->permittedPeers.nmemb = newMemb;
	pThis->pEngine->dbgprint((char*)"librelp: SRV permitted peer added: '%s'\n", peer);

finalize_it:
	LEAVE_RELPFUNC;
}


/* set the user pointer. Whatever value the user provides is accepted.
 * rgerhards, 2008-07-08
 */
PART_OF_API relpRetVal
relpSrvSetUsrPtr(relpSrv_t *const pThis, void *pUsr)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	pThis->pUsr = pUsr;
	LEAVE_RELPFUNC;
}

PART_OF_API relpRetVal
relpSrvSetMaxDataSize(relpSrv_t *const pThis, size_t bytes)
{
	RELPOBJ_assert(pThis, Srv);
	pThis->receiveLimit.bytes = bytes;
	pThis->receiveLimit.configured = true;
	return RELP_RET_OK;
}

size_t
relpSrvGetReceiveLimit(const relpSrv_t *const pThis)
{
	RELPOBJ_assert(pThis, Srv);
	/* Both zero and SIZE_MAX are valid explicit limits. */
	return pThis->receiveLimit.configured ? pThis->receiveLimit.bytes : RELP_DFLT_MAX_DATA_SIZE;
}

PART_OF_API relpRetVal LIBRELP_ATTR_NONNULL()
relpSrvSetOversizeMode(relpSrv_t *const pThis, const int oversizeMode)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	if(   oversizeMode != RELP_OVERSIZE_ABORT
	   && oversizeMode != RELP_OVERSIZE_TRUNCATE
	   && oversizeMode != RELP_OVERSIZE_ACCEPT) {
		ABORT_FINALIZE(RELP_RET_PARAM_ERROR);
	}
	pThis->oversizeMode = oversizeMode;
finalize_it:
	LEAVE_RELPFUNC;
}

/* Update the owned endpoint string only after the copy succeeds.
 * NULL clears the setting and restores the listener default.
 */
static relpRetVal
relpSrvSetEndpointString(unsigned char **const current, const unsigned char *const value)
{
	unsigned char *copy = NULL;

	if(value != NULL) {
		copy = (unsigned char*)strdup((const char*)value);
		if(copy == NULL)
			return RELP_RET_OUT_OF_MEMORY;
	}

	free(*current);
	*current = copy;
	return RELP_RET_OK;
}

/* NULL selects the default RELP service. */
PART_OF_API relpRetVal
relpSrvSetLstnPort(relpSrv_t *const pThis, unsigned char *pLstnPort)
{
	RELPOBJ_assert(pThis, Srv);
	return relpSrvSetEndpointString(&pThis->pLstnPort, pLstnPort);
}

/* NULL leaves the node unspecified so the listener can bind wildcard addresses. */
PART_OF_API relpRetVal
relpSrvSetLstnAddr(relpSrv_t *const pThis, unsigned char *pLstnAddr)
{
	RELPOBJ_assert(pThis, Srv);
	return relpSrvSetEndpointString(&pThis->bindNode, pLstnAddr);
}

/* mode==NULL is valid and means "no change" */
PART_OF_API relpRetVal
relpSrvSetAuthMode(relpSrv_t *const pThis, char *mode)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	if(mode == NULL)
		FINALIZE;

	if(!strcasecmp(mode, "fingerprint"))
		pThis->authmode = eRelpAuthMode_Fingerprint;
	else if(!strcasecmp(mode, "name"))
		pThis->authmode = eRelpAuthMode_Name;
	else if(!strcasecmp(mode, "certvalid"))
		pThis->authmode = eRelpAuthMode_CertValid;
	else
		ABORT_FINALIZE(RELP_RET_INVLD_AUTH_MD);

finalize_it:
	LEAVE_RELPFUNC;
}

/* set the IPv4/v6 type to be used. Default is both (PF_UNSPEC)
 * rgerhards, 2013-03-15
 */
relpRetVal
relpSrvSetFamily(relpSrv_t *const pThis, int ai_family)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	pThis->ai_family = ai_family;
	LEAVE_RELPFUNC;
}

/* set the GnuTLS priority string. Providing NULL does re-set
 * any previously set string. -- rgerhards, 2013-06-12
 */
PART_OF_API relpRetVal
relpSrvSetGnuTLSPriString(relpSrv_t *const pThis, char *pristr)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	free(pThis->pristring);
	if(pristr == NULL) {
		pThis->pristring = NULL;
	} else {
		if((pThis->pristring = strdup(pristr)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}

PART_OF_API relpRetVal
relpSrvSetCACert(relpSrv_t *const pThis, char *cert)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	free(pThis->caCertFile);
	if(cert == NULL) {
		pThis->caCertFile = NULL;
	} else {
		if((pThis->caCertFile = strdup(cert)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}
PART_OF_API relpRetVal
relpSrvSetOwnCert(relpSrv_t *const pThis, char *cert)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	free(pThis->ownCertFile);
	if(cert == NULL) {
		pThis->ownCertFile = NULL;
	} else {
		if((pThis->ownCertFile = strdup(cert)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}
PART_OF_API relpRetVal
relpSrvSetPrivKey(relpSrv_t *const pThis, char *cert)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	free(pThis->privKey);
	if(cert == NULL) {
		pThis->privKey = NULL;
	} else {
		if((pThis->privKey = strdup(cert)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}

PART_OF_API relpRetVal
relpSrvSetTlsConfigCmd(relpSrv_t *const pThis, char *cfgcmd)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	free(pThis->tlsConfigCmd);
	if(cfgcmd == NULL) {
		pThis->tlsConfigCmd = NULL;
	} else {
		if((pThis->tlsConfigCmd = strdup(cfgcmd)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}
PART_OF_API void
relpSrvSetDHBits(relpSrv_t *const pThis, int bits)
{
	pThis->dhBits = bits;
}
PART_OF_API relpRetVal
relpSrvEnableTLS2(relpSrv_t *const pThis)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	pThis->bEnableTLS = 1;
#if !(defined(ENABLE_TLS) || defined(ENABLE_TLS_OPENSSL))
	iRet = RELP_RET_ERR_NO_TLS;
#endif /* !(defined(ENABLE_TLS) || defined(ENABLE_TLS_OPENSSL)) */
	LEAVE_RELPFUNC;
}
PART_OF_API relpRetVal
relpSrvEnableTLSZip2(relpSrv_t *const pThis)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	pThis->bEnableTLSZip = 1;
#if !(defined(ENABLE_TLS) || defined(ENABLE_TLS_OPENSSL))
	iRet = RELP_RET_ERR_NO_TLS;
#endif /* !(defined(ENABLE_TLS) || defined(ENABLE_TLS_OPENSSL)) */
	LEAVE_RELPFUNC;
}
PART_OF_API void
relpSrvEnableTLS(relpSrv_t *const pThis)
{
	relpSrvEnableTLS2(pThis);
}
PART_OF_API void
relpSrvEnableTLSZip(relpSrv_t *const pThis)
{
	relpSrvEnableTLSZip2(pThis);
}

PART_OF_API void
relpSrvSetKeepAlive(relpSrv_t *const pThis,
	const int bEnabled,
	const int iKeepAliveIntvl,
	const int iKeepAliveProbes,
	const int iKeepAliveTime)
{
	pThis->bKeepAlive = bEnabled;
	pThis->iKeepAliveIntvl = iKeepAliveIntvl;
	pThis->iKeepAliveProbes = iKeepAliveProbes;
	pThis->iKeepAliveTime = iKeepAliveTime;
}

/* start a relp server - the server object must have all properties set
 * rgerhards, 2008-03-17
 */
relpRetVal
relpSrvRun(relpSrv_t *const pThis)
{
	relpTcp_t *pTcp = NULL;
	unsigned char defaultPort[] = RELP_STRINGIFY(RELP_DFLT_PORT);
	unsigned char *port;

	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);

	CHKRet(relpTcpConstruct(&pTcp, pThis->pEngine, RELP_SRV_CONN, pThis));
	relpTcpSetUsrPtr(pTcp, pThis->pUsr);
	if(pThis->bEnableTLS) {
		CHKRet(relpTcpEnableTLS(pTcp));
		if(pThis->bEnableTLSZip) {
			CHKRet(relpTcpEnableTLSZip(pTcp));
		}
		relpTcpSetDHBits(pTcp, pThis->dhBits);
		CHKRet(relpTcpSetGnuTLSPriString(pTcp, pThis->pristring));
		CHKRet(relpTcpSetTlsConfigCmd(pTcp, pThis->tlsConfigCmd));
		CHKRet(relpTcpSetAuthMode(pTcp, pThis->authmode));
		CHKRet(relpTcpSetCACert(pTcp, pThis->caCertFile));
		CHKRet(relpTcpSetOwnCert(pTcp, pThis->ownCertFile));
		CHKRet(relpTcpSetPrivKey(pTcp, pThis->privKey));
		CHKRet(relpTcpSetPermittedPeers(pTcp, &(pThis->permittedPeers)));
	}
	port = pThis->pLstnPort;
	if(port == NULL)
		port = defaultPort;
	CHKRet(relpTcpLstnInit(pTcp, port, pThis->bindNode, pThis->ai_family));

	pThis->pTcp = pTcp;
	pTcp = NULL;

finalize_it:
	if(pTcp != NULL)
		relpTcpDestruct(&pTcp);
	LEAVE_RELPFUNC;
}
