/* The relp server.
 *
 * Copyright 2008-2018 by Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Librelp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Librelp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Librelp.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 *
 * If the terms of the GPL are unsuitable for your needs, you may obtain
 * a commercial license from Adiscon. Contact sales@adiscon.com for further
 * details.
 *
 * ALL CONTRIBUTORS PLEASE NOTE that by sending contributions, you assign
 * your copyright to Adiscon GmbH, Germany. This is necessary to permit the
 * dual-licensing set forth here. Our apologies for this inconvenience, but
 * we sincerely believe that the dual-licensing model helps us provide great
 * free software while at the same time obtaining some funding for further
 * development.
 */
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/socket.h>
#include "relp.h"
#include "relpsrv.h"
#include "tcp.h"



/** Construct a RELP srv instance
 * This is the first thing that a caller must do before calling any
 * RELP function. The relp srv must only destructed after all RELP
 * operations have been finished.
 */
relpRetVal PART_OF_API
relpSrvConstruct(relpSrv_t **ppThis, relpEngine_t *pEngine)
{
	relpSrv_t *pThis;

	ENTER_RELPFUNC;
	assert(ppThis != NULL);
	if((pThis = calloc(1, sizeof(relpSrv_t))) == NULL) {
		ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}

	RELP_CORE_CONSTRUCTOR(pThis, Srv);
	pThis->pEngine = pEngine;
	pThis->stateCmdSyslog = pEngine->stateCmdSyslog;
	pThis->ai_family = PF_UNSPEC;
	pThis->dhBits = DEFAULT_DH_BITS;
	pThis->pristring = NULL;
	pThis->authmode = eRelpAuthMode_None;
	pThis->caCertFile = NULL;
	pThis->ownCertFile = NULL;
	pThis->privKey = NULL;
	pThis->tlsConfigCmd = NULL;
	pThis->permittedPeers.nmemb = 0;
	pThis->maxDataSize = RELP_DFLT_MAX_DATA_SIZE;
	pThis->oversizeMode = RELP_DFLT_OVERSIZE_MODE;

	*ppThis = pThis;

finalize_it:
	LEAVE_RELPFUNC;
}


/** Destruct a RELP srv instance
 */
relpRetVal PART_OF_API
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
	free(pThis->pLstnAddr);
	free(pThis->pristring);
	free(pThis->caCertFile);
	free(pThis->ownCertFile);
	free(pThis->privKey);
	free(pThis->tlsConfigCmd);
	for(i = 0 ; i < pThis->permittedPeers.nmemb ; ++i)
		free(pThis->permittedPeers.name[i]);
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
relpRetVal PART_OF_API
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
	if((newName[newMemb - 1] = strdup(peer)) == NULL) {
		free(newName);
		ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
	pThis->permittedPeers.name = newName;
	pThis->permittedPeers.nmemb = newMemb;
	pThis->pEngine->dbgprint((char*)"librelp: SRV permitted peer added: '%s'\n", peer);

finalize_it:
	LEAVE_RELPFUNC;
}


/* set the user pointer. Whatever value the user provides is accepted.
 * rgerhards, 2008-07-08
 */
relpRetVal PART_OF_API
relpSrvSetUsrPtr(relpSrv_t *const pThis, void *pUsr)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	pThis->pUsr = pUsr;
	LEAVE_RELPFUNC;
}

relpRetVal PART_OF_API
relpSrvSetMaxDataSize(relpSrv_t *const pThis, size_t maxSize) {
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	pThis->maxDataSize = maxSize;
	LEAVE_RELPFUNC;
}

relpRetVal PART_OF_API LIBRELP_ATTR_NONNULL()
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

/* set the listen port inside the relp server. If NULL is provided, the default port
 * is used. The provided string is always copied, it is the caller's duty to
 * free the passed-in string.
 * rgerhards, 2008-03-17
 */
relpRetVal PART_OF_API
relpSrvSetLstnPort(relpSrv_t *const pThis, unsigned char *pLstnPort)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);

	/* first free old value */
	free(pThis->pLstnPort);
	pThis->pLstnPort = NULL;

	if(pLstnPort != NULL) {
		if((pThis->pLstnPort = (unsigned char*) strdup((char*)pLstnPort)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}

finalize_it:
	LEAVE_RELPFUNC;
}

/* set the address inside the relp server. If NULL is provided, the server
 * will bind to all interfaces. The provided string is always copied, it is the caller's duty to
 * free the passed-in string.
 * perlei, 2018-04-19
 */
relpRetVal PART_OF_API
relpSrvSetLstnAddr(relpSrv_t *const pThis, unsigned char *pLstnAddr)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);

	/* first free old value */
	free(pThis->pLstnAddr);
	pThis->pLstnAddr = NULL;

	if(pLstnAddr != NULL) {
		if((pThis->pLstnAddr = (unsigned char*) strdup((char*)pLstnAddr)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}

finalize_it:
	LEAVE_RELPFUNC;
}

/* mode==NULL is valid and means "no change" */
relpRetVal PART_OF_API
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
relpRetVal PART_OF_API
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
relpRetVal PART_OF_API
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

relpRetVal PART_OF_API
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
relpRetVal PART_OF_API
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
relpRetVal PART_OF_API
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

relpRetVal PART_OF_API
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
void PART_OF_API
relpSrvSetDHBits(relpSrv_t *const pThis, int bits)
{
	pThis->dhBits = bits;
}
relpRetVal PART_OF_API
relpSrvEnableTLS2(relpSrv_t LIBRELP_ATTR_UNUSED *pThis)
{
	ENTER_RELPFUNC;
#if defined(ENABLE_TLS) || defined(ENABLE_TLS_OPENSSL)
	pThis->bEnableTLS = 1;
#else
	iRet = RELP_RET_ERR_NO_TLS;
#endif /* #ifdef ENABLE_TLS | ENABLE_TLS_OPENSSL */
	LEAVE_RELPFUNC;
}
relpRetVal PART_OF_API
relpSrvEnableTLSZip2(relpSrv_t LIBRELP_ATTR_UNUSED *pThis)
{
	ENTER_RELPFUNC;
#if defined(ENABLE_TLS) || defined(ENABLE_TLS_OPENSSL)
	pThis->bEnableTLSZip = 1;
#else
	iRet = RELP_RET_ERR_NO_TLS;
#endif /* #ifdef ENABLE_TLS | ENABLE_TLS_OPENSSL */
	LEAVE_RELPFUNC;
}
void PART_OF_API
relpSrvEnableTLS(relpSrv_t *const pThis)
{
	relpSrvEnableTLS2(pThis);
}
void PART_OF_API
relpSrvEnableTLSZip(relpSrv_t *const pThis)
{
	relpSrvEnableTLSZip2(pThis);
}

void PART_OF_API
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
relpRetVal PART_OF_API
relpSrvRun(relpSrv_t *const pThis)
{
	relpTcp_t *pTcp;

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
	CHKRet(relpTcpLstnInit(pTcp, (pThis->pLstnPort == NULL) ?
		(unsigned char*) RELP_DFLT_PORT : pThis->pLstnPort,
		(unsigned char*) pThis->pLstnAddr,
		pThis->ai_family));

	pThis->pTcp = pTcp;

finalize_it:
	if(iRet != RELP_RET_OK) {
		if(pThis->pTcp != NULL)
			relpTcpDestruct(&pTcp);
	}

	LEAVE_RELPFUNC;
}


/* Enable or disable a command. Note that a command can not be enabled once
 * it has been set to forbidden! There will be no error return state in this
 * case.
 * rgerhards, 2008-03-27
 */
relpRetVal PART_OF_API
relpSrvSetEnableCmd(relpSrv_t *const pThis, unsigned char *const pszCmd, const relpCmdEnaState_t stateCmd)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Srv);
	assert(pszCmd != NULL);

pThis->pEngine->dbgprint((char*)"SRV SetEnableCmd in syslog cmd state: %d\n", pThis->stateCmdSyslog);
	if(!strcmp((char*)pszCmd, "syslog")) {
		if(pThis->stateCmdSyslog != eRelpCmdState_Forbidden)
			pThis->stateCmdSyslog = stateCmd;
	} else {
		pThis->pEngine->dbgprint((char*)"tried to set unknown command '%s' to %d\n", pszCmd, stateCmd);
		ABORT_FINALIZE(RELP_RET_UNKNOWN_CMD);
	}

finalize_it:
pThis->pEngine->dbgprint((char*)"SRV SetEnableCmd out syslog cmd state: %d, iRet %d\n", pThis->stateCmdSyslog, iRet);
	LEAVE_RELPFUNC;
}
