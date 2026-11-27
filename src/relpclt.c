/* SPDX-License-Identifier: Apache-2.0 */

/* The relp client.
 *
 * Copyright 2008-2020 by Rainer Gerhards and Adiscon GmbH.
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
#include <string.h>
#include "relp.h"
#include "relpsess.h"
#include "relpclt.h"


/** Construct a RELP clt instance
 * This is the first thing that a caller must do before calling any
 * RELP function. The relp clt must only destructed after all RELP
 * operations have been finished.
 */
relpRetVal
relpCltConstruct(relpClt_t **ppThis, relpEngine_t *const pEngine)
{
	relpClt_t *pThis;

	ENTER_RELPFUNC;
	assert(ppThis != NULL);
	if((pThis = calloc(1, sizeof(relpClt_t))) == NULL) {
		ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}

	RELP_CORE_CONSTRUCTOR(pThis, Clt);
	pThis->pEngine = pEngine;
	pThis->timeout = 90; /* 90-second timeout is the default */
	pThis->pUsr = NULL;
	pThis->authmode = eRelpAuthMode_None;
	pThis->pristring = NULL;
	pThis->caCertFile = NULL;
	pThis->ownCertFile = NULL;
	pThis->privKey = NULL;
	pThis->tlsConfigCmd = NULL;
	pThis->permittedPeers.nmemb = 0;

	*ppThis = pThis;

finalize_it:
	LEAVE_RELPFUNC;
}


/** Destruct a RELP clt instance
 */
relpRetVal
relpCltDestruct(relpClt_t **ppThis)
{
	int i;
	relpClt_t *pThis;

	ENTER_RELPFUNC;
	assert(ppThis != NULL);
	pThis = *ppThis;
	RELPOBJ_assert(pThis, Clt);

	if(pThis->pSess != NULL)
		relpSessDestruct(&pThis->pSess);
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

	/* done with de-init work, now free clt object itself */
	free(pThis);
	*ppThis = NULL;

	LEAVE_RELPFUNC;
}


/** open a relp session to a remote peer
 * remote servers parameters must already have been set.
 * rgerhards, 2008-03-19
 */
PART_OF_API relpRetVal
relpCltConnect(relpClt_t *const pThis, int protFamily, unsigned char *port, unsigned char *host)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);

	CHKRet(relpSessConstruct(&pThis->pSess, pThis->pEngine, RELP_CLT_CONN, pThis, pThis->pUsr));
	CHKRet(relpSessSetTimeout(pThis->pSess, pThis->timeout));
	CHKRet(relpSessSetWindowSize(pThis->pSess, pThis->sizeWindow));
	pThis->pSess->connTimeout = pThis->connectTimeoutOverride ? pThis->connectTimeoutOverride
		: RELP_DFLT_CONN_TIMEOUT;
	pThis->pSess->sourceBind = pThis->sourceBind;
	if(pThis->bEnableTLS) {
		CHKRet(relpSessEnableTLS(pThis->pSess));
		if(pThis->bEnableTLSZip) {
			CHKRet(relpSessEnableTLSZip(pThis->pSess));
		}
		CHKRet(relpSessSetGnuTLSPriString(pThis->pSess, pThis->pristring));
		CHKRet(relpSessSetTlsConfigCmd(pThis->pSess, pThis->tlsConfigCmd));
		CHKRet(relpSessSetCACert(pThis->pSess, pThis->caCertFile));
		CHKRet(relpSessSetOwnCert(pThis->pSess, pThis->ownCertFile));
		CHKRet(relpSessSetPrivKey(pThis->pSess, pThis->privKey));
		CHKRet(relpSessSetAuthMode(pThis->pSess, pThis->authmode));
		CHKRet(relpSessSetPermittedPeers(pThis->pSess, &pThis->permittedPeers));
	}
	CHKRet(relpSessConnect(pThis->pSess, protFamily, port, host));

finalize_it:
	if(iRet != RELP_RET_OK) {
		if(pThis->pSess != NULL) {
			relpSessDestruct(&pThis->pSess);
		}
	}

	LEAVE_RELPFUNC;
}


/** Try to reconnect a broken session to the remote
 * server. The main difference to relpCltConnect() is that the
 * session already exists and retains the original destination.
 * rgerhards, 2008-03-23
 */
PART_OF_API relpRetVal
relpCltReconnect(relpClt_t *const pThis)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	RELPOBJ_assert(pThis->pSess, Sess);

	/* A reconnect opens a new socket and uses the latest source binding. */
	pThis->pSess->sourceBind = pThis->sourceBind;
	CHKRet(relpSessTryReestablish(pThis->pSess));

finalize_it:
	LEAVE_RELPFUNC;
}


/** Set the relp window size for this client. Value 0 means
 * that the default value is to be used.
 */
PART_OF_API relpRetVal
relpCltSetWindowSize(relpClt_t *const pThis, int sizeWindow)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	if(sizeWindow < 0)
		ABORT_FINALIZE(RELP_RET_ERR_INVAL);
	if(sizeWindow != 0)
		pThis->sizeWindow = sizeWindow;
finalize_it:
	LEAVE_RELPFUNC;
}

/** Set the timeout value for this client.  */
PART_OF_API relpRetVal
relpCltSetTimeout(relpClt_t *const pThis, unsigned timeout)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	pThis->timeout = timeout;
	LEAVE_RELPFUNC;
}

/** Set the client socket connection timeout in seconds. Zero leaves it unchanged. */
PART_OF_API relpRetVal
relpCltSetConnTimeout(relpClt_t *const pThis, const int seconds)
{
	RELPOBJ_assert(pThis, Clt);

	if(seconds > 0) {
		pThis->connectTimeoutOverride = seconds;
	}
	return seconds < 0 ? RELP_RET_ERR_INVAL : RELP_RET_OK;
}

PART_OF_API relpRetVal
relpCltSetClientIP(relpClt_t *const pThis, unsigned char *ipAddr)
{
	RELPOBJ_assert(pThis, Clt);
	return relpSourceBindResolve(&pThis->sourceBind, (const char *)ipAddr);
}

PART_OF_API relpRetVal
relpCltAddPermittedPeer(relpClt_t *const pThis, char *peer)
{
	char **newName;
	int newMemb;
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
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
	pThis->pEngine->dbgprint((char*)"librelp: CLT permitted peer added: '%s'\n", peer);

finalize_it:
	LEAVE_RELPFUNC;
}

PART_OF_API relpRetVal
relpCltSetUsrPtr(relpClt_t *const pThis, void *pUsr)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	pThis->pUsr = pUsr;
	LEAVE_RELPFUNC;
}

/* Note: mode==NULL is valid and means "no change" */
PART_OF_API relpRetVal
relpCltSetAuthMode(relpClt_t *const pThis, char *mode)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
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

/* set the GnuTLS priority string. Providing NULL does re-set
 * any previously set string. -- rgerhards, 2013-06-12
 */
PART_OF_API relpRetVal
relpCltSetGnuTLSPriString(relpClt_t *const pThis, char *pristr)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
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
relpCltSetCACert(relpClt_t *const pThis, char *file)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	free(pThis->caCertFile);
	if(file == NULL) {
		pThis->caCertFile = NULL;
	} else {
		if((pThis->caCertFile = strdup(file)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}
PART_OF_API relpRetVal
relpCltSetOwnCert(relpClt_t *const pThis, char *file)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	free(pThis->ownCertFile);
	if(file == NULL) {
		pThis->ownCertFile = NULL;
	} else {
		if((pThis->ownCertFile = strdup(file)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}
PART_OF_API relpRetVal
relpCltSetPrivKey(relpClt_t *const pThis, char *file)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	free(pThis->privKey);
	if(file == NULL) {
		pThis->privKey = NULL;
	} else {
		if((pThis->privKey = strdup(file)) == NULL)
			ABORT_FINALIZE(RELP_RET_OUT_OF_MEMORY);
	}
finalize_it:
	LEAVE_RELPFUNC;
}
PART_OF_API relpRetVal
relpCltSetTlsConfigCmd(relpClt_t *const pThis, char *cfgcmd)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
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
/* Enable TLS mode. */
PART_OF_API relpRetVal
relpCltEnableTLS(relpClt_t *const pThis)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	pThis->bEnableTLS = 1;
	LEAVE_RELPFUNC;
}

PART_OF_API relpRetVal
relpCltEnableTLSZip(relpClt_t *const pThis)
{
	ENTER_RELPFUNC;
	RELPOBJ_assert(pThis, Clt);
	pThis->bEnableTLSZip = 1;
	LEAVE_RELPFUNC;
}

/* this function is called to hint librelp that a "burst" of data is to be
 * sent. librelp can than try to optimize it's handling.
 * The function is intentionally void as it must operate in a way that
 * does not interfere with normal operations.
 */
PART_OF_API void
relpCltHintBurstBegin(relpClt_t *const pThis)
{
	relpTcpHintBurstBegin(pThis->pSess->pTcp);
}
/* this is the counterpart to relpCltHintBurstBegin -- see there for doc */
PART_OF_API void
relpCltHintBurstEnd(relpClt_t *const pThis)
{
	relpTcpHintBurstEnd(pThis->pSess->pTcp);
}

/* Send a syslog message through RELP. The session must be established.
 * The provided message buffer is not touched by this function. The caller
 * must free it if it is no longer needed.
 * rgerhards, 2008-03-20
 */
PART_OF_API relpRetVal
relpCltSendSyslog(relpClt_t *const pThis, unsigned char *const pMsg, const size_t lenMsg)
{

	ENTER_RELPFUNC;
	if(pThis == NULL || pThis->objID != eRelpObj_Clt)
		ABORT_FINALIZE(RELP_RET_INVALID_HDL);

	CHKRet(relpSessSendSyslog(pThis->pSess, pMsg, lenMsg));

finalize_it:
	LEAVE_RELPFUNC;
}
