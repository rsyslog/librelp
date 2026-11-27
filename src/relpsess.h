/* SPDX-License-Identifier: Apache-2.0 */

/* The RELPSESS object.
 *
 * Copyright 2008-2016 by Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 *
 * ALL CONTRIBUTORS PLEASE NOTE that by sending contributions, you assign
 * your copyright to Adiscon GmbH, Germany.
 */
#ifndef RELPSESS_H_INCLUDED
#define	RELPSESS_H_INCLUDED

#include <pthread.h>
#include <time.h>

#include "relpsrv.h"
#include "sourcebind.h"

/* unacked msgs linked list */
typedef struct replSessUnacked_s {
	struct replSessUnacked_s *pNext;
	struct replSessUnacked_s *pPrev;
	struct relpSendbuf_s *pSendbuf; /**< the unacked message */
} relpSessUnacked_t;

/* relp session state */
typedef enum relpSessState_e {
	eRelpSessState_DISCONNECTED = 0,  /* session is disconnected and must be destructed */
	eRelpSessState_PRE_INIT = 1,
	eRelpSessState_INIT_CMD_SENT = 2,
	eRelpSessState_INIT_RSP_RCVD = 3,
	eRelpSessState_READY_TO_SEND = 4,
	eRelpSessState_WINDOW_FULL = 5,
	eRelpSessState_CLOSE_CMD_SENT = 6, /* once we are in a close state, we can not send any  */
	eRelpSessState_CLOSE_RSP_RCVD = 7, /* other commands */
	eRelpSessState_BROKEN = 9   /**< something went wrong, session must be dropped */
} relpSessState_t;

typedef enum relpSessType_e {
	eRelpSess_Server = 0,
	eRelpSess_Client = 1
} relpSessType_t; /* what type of session are we? */


/* the RELPSESS object
 * rgerhards, 2008-03-16
 */
struct relpSess_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	relpSessType_t sessType;	/**< session type: 0 - server, 1 - client */
	int bServerConnOpen;	/**< server part: is connection established? */
	time_t acceptedAt; /* monotonic seconds, server sessions only */
	time_t lastActivity; /* monotonic seconds of last complete received frame */
	void *pUsr;		/**< user provided pointer (opaque data) */
	relpTcp_t *pTcp;	/**< our sockt to the remote peer */
	struct relpFrame_s *pCurrRcvFrame; /**< the current receive frame (a buffer) */
	relpTxnr_t txnr;	/**< next txnr expected when receiving or to be used when sending */
	size_t maxDataSize;
	size_t maxCharsStore;  /**< maximum number of message chars to store - support for truncation mode */
	pthread_mutex_t mutSend; /**< mutex for send operation (make sure txnr is correct) */
	relpSrv_t *pSrv;	   /**< a pointer to our server object, if NULL, we belong to a client */
	relpClt_t *pClt;	   /**< ptr to our client; only valid if pSrv == NULL */

	/* connection parameters */
	int protocolVersion; /* relp protocol version in use in this session */
	/* Status of commands as supported in this session. */
	relpCmdEnaState_t stateCmdSyslog;
	int bEnableTLS;
	int bEnableTLSZip;
	char *pristring;
	char *caCertFile;
	char *ownCertFile;
	char *privKeyFile;
	char *tlsConfigCmd;	/**< optional configuration command property for TLS libs **/
	relpAuthMode_t authmode;
	relpPermittedPeers_t permittedPeers;

	/* save the following for auto-reconnect case */
	int protFamily;
	unsigned char *srvPort;
	unsigned char *srvAddr;
	relpSourceBind_t sourceBind;

	/* properties needed for server operation */
	struct relpSendq_s *pSendq; /**< our send queue */

	/* properties needed for client operation */
	int sizeWindow;	/**< size of our app-level communications window */
	unsigned timeout; /**< timeout after which session is to be considered broken */
	relpSessState_t sessState; /**< state of our session */
	/* linked list of frames with outstanding "rsp" */
	relpSessUnacked_t *pUnackedLstRoot;
	relpSessUnacked_t *pUnackedLstLast;
	int lenUnackedLst;
};

/* macros for quick member access */
#define relpSessGetSock(pThis)  (relpTcpGetSock((pThis)->pTcp))
#define relpSessGetSessState(pThis) ((pThis)->sessState)
#define relpSessSetSessState(pThis, state) ((pThis)->sessState = (state))

#include "relpframe.h" /* this needs to be done after relpSess_t is defined! */
#include "sendbuf.h"
#include "sendq.h"

/* inlines */
static inline int
relpSessTcpRequiresRtry(relpSess_t *pThis)
{
	return pThis->pTcp->rtryOp != relpTCP_RETRY_none;
}

/* prototypes */
relpRetVal relpSessConstruct(relpSess_t **ppThis, relpEngine_t *pEngine, int connType, void *pParent, void*pUsr);
relpRetVal relpSessDestruct(relpSess_t **ppThis);
relpRetVal relpSessAcceptAndConstruct(relpSess_t **ppThis, relpSrv_t *pSrv, int sock);
relpRetVal relpSessRcvData(relpSess_t *pThis);
relpRetVal relpSessSendFrame(relpSess_t *pThis, relpFrame_t *pFrame);
relpRetVal relpSessSendResponse(relpSess_t *pThis, relpTxnr_t txnr, unsigned char *pData, size_t lenData);
relpRetVal relpSessSndData(relpSess_t *pThis);
relpRetVal relpSessSendCommand(relpSess_t *pThis, unsigned char *pCmd, size_t lenCmd,
		    unsigned char *pData, size_t lenData, relpRetVal (*rspHdlr)(relpSess_t*,relpFrame_t*));
relpRetVal relpSessConnect(relpSess_t *pThis, int protFamily, unsigned char *port, unsigned char *host,
			 int connectTimeoutSeconds);
relpRetVal relpSessAddUnacked(relpSess_t *pThis, relpSendbuf_t *pSendbuf);
relpRetVal relpSessGetUnacked(relpSess_t *pThis, relpSendbuf_t **ppSendbuf, relpTxnr_t txnr);
relpRetVal relpSessTryReestablish(relpSess_t *pThis, int connectTimeoutSeconds);
relpRetVal relpSessSetProtocolVersion(relpSess_t *pThis, int protocolVersion);
relpRetVal relpSessSetTimeout(relpSess_t *pThis, unsigned timeout);
relpRetVal relpSessSetWindowSize(relpSess_t *pThis, int sizeWindow);
relpRetVal relpSessEnableTLS(relpSess_t *pThis);
relpRetVal relpSessEnableTLSZip(relpSess_t *pThis);
relpRetVal relpSessSetAuthMode(relpSess_t *pThis, relpAuthMode_t authmode);
relpRetVal relpSessSetGnuTLSPriString(relpSess_t *pThis, char *pristr);
relpRetVal relpSessSetCACert(relpSess_t *pThis, char *cert);
relpRetVal relpSessSetOwnCert(relpSess_t *pThis, char *cert);
relpRetVal relpSessSetPrivKey(relpSess_t *pThis, char *cert);
relpRetVal relpSessSetTlsConfigCmd(relpSess_t *pThis, char *cfgcmd);
relpRetVal relpSessConstructOffers(relpSess_t *pThis, relpOffers_t **ppOffers);
relpRetVal relpSessSetPermittedPeers(relpSess_t *pThis, relpPermittedPeers_t *pPeers);
relpRetVal relpSessSetUsrPtr(relpSess_t *pThis, void *pUsr);
relpRetVal relpSessSendSyslog(relpSess_t *pThis, unsigned char *pMsg, size_t lenMsg);
relpRetVal relpSessSetEnableCmd(relpSess_t *pThis, unsigned char *pszCmd, relpCmdEnaState_t stateCmd);


#endif /* #ifndef RELPSESS_H_INCLUDED */
