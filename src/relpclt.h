/* SPDX-License-Identifier: Apache-2.0 */

/* The RELPCLT object.
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
#ifndef RELPCLT_H_INCLUDED
#define	RELPCLT_H_INCLUDED

#include "sourcebind.h"

/* default socket connect timeout in seconds, used unless the caller
 * sets one via relpCltSetConnTimeout() */
#define RELP_DFLT_CONN_TIMEOUT 10

/* the RELPCLT object
 * rgerhards, 2008-03-16
 */
struct relpClt_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	relpSess_t *pSess;	/**< our session (the one and only!) */
	void *pUsr;		/**< user pointer (opaque data) */
	int bEnableTLS;		/**< is TLS to be used? */
	int bEnableTLSZip;	/**< is compression to be used together with TLS? */
	int sizeWindow;		/**< size of our app-level communications window */
	char *pristring;	/**< priority string for GnuTLS */
	relpAuthMode_t authmode;
	char *caCertFile;
	char *ownCertFile;
	char *privKey;
	char *tlsConfigCmd;	/**< optional configuration command property for TLS libs **/
	relpPermittedPeers_t permittedPeers;
	int protFamily;		/**< protocol family to connect over (IPv4, v6, ...) */
	unsigned char *port;	/**< server port to connect to */
	unsigned char *host;	/**< host(name) to connect to */
	relpSourceBind_t sourceBind;
	unsigned timeout;	/**< session timeout */
	int connectTimeoutOverride; /**< connection timeout in seconds (0 means default) */
};


/* prototypes */
relpRetVal relpCltConstruct(relpClt_t **ppThis, relpEngine_t *pEngine);
relpRetVal relpCltDestruct(relpClt_t **ppThis);

#endif /* #ifndef RELPCLT_H_INCLUDED */
