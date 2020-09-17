/* The mapping for relp over TCP.
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
 * along with librelp.  If not, see <http://www.gnu.org/licenses/>.
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
#ifndef RELPTCP_H_INCLUDED
#define	RELPTCP_H_INCLUDED

#include <stdint.h>
#ifdef ENABLE_TLS
#       include <gnutls/gnutls.h>
#endif
#ifdef ENABLE_TLS_OPENSSL
#	include <openssl/ssl.h>
#endif
#include "relp.h"

typedef enum { relpTCP_RETRY_none = 0,
	relpTCP_RETRY_handshake = 1,
	relpTCP_RETRY_recv = 2,
	relpTCP_RETRY_send = 3 } relpTcpRtryState_t;

#define RELP_SRV_CONN 0	/**< this conection is a server connection */
#define RELP_CLT_CONN 1	/**< this conection is a client connection */


/* The tcp module uses an extended version of the permittedPeers structure,
 * as it finally needs to "compile" patters that contain wildcards. Doing
 * that on the fly would not make sense from a performance PoV. Note that
 * we do not use this exteded structure in highe layers, as it is not
 * needed there and would at least make things lool much more complicated
 * than they must be.
 */

/* if we have wildcards inside permitted peers, we need to maintain
 * a separate linked list for the wildcard components.
 */
typedef struct tcpPermittedPeerWildcardComp_s {
	char *pszDomainPart;
	int16_t lenDomainPart;
	enum {
		tcpPEER_WILDCARD_NONE = 0,		/**< no wildcard in this entry */
		tcpPEER_WILDCARD_AT_START = 1,	/**< wildcard at start of entry (*name) */
		tcpPEER_WILDCARD_AT_END = 2,	/**< wildcard at end of entry (name*) */
		tcpPEER_WILDCARD_MATCH_ALL = 3,	/**< only * wildcard, matches all values */
		tcpPEER_WILDCARD_EMPTY_COMPONENT = 4/**< special case: domain component empty (e.g. "..") */
	} wildcardType;
	struct tcpPermittedPeerWildcardComp_s *pNext;
} tcpPermittedPeerWildcardComp_t;

typedef struct {
		char *name;
		tcpPermittedPeerWildcardComp_t *wildcardRoot;
		tcpPermittedPeerWildcardComp_t *wildcardLast;
} tcpPermittedPeerEntry_t;
/* a structure to store permitted peer information (a type of ACL) */
typedef struct tcpPermittedPeers_s {
	int nmemb;
	tcpPermittedPeerEntry_t *peer;
} tcpPermittedPeers_t;

#ifdef ENABLE_TLS_OPENSSL
typedef enum {
	osslRtry_None = 0,	/**< no call needs to be retried */
	osslRtry_handshake = 1,
	osslRtry_recv = 2
} osslRtryCall_t;		/**< IDs of calls that needs to be retried */

typedef enum {
	osslServer = 0,		/**< Server SSL Object */
	osslClient = 1		/**< Client SSL Object */
} osslSslState_t;
#endif

/* the RELPTCP object
 * rgerhards, 2008-03-16
 */
typedef struct relpTcp_s {
	BEGIN_RELP_OBJ;
	relpEngine_t *pEngine;
	void *pUsr;		   /**< user pointer for callbacks */
	relpSrv_t *pSrv;	   /**< a pointer to our server object, if NULL, we belong to a client */
	relpClt_t *pClt;	   /**< ptr to our client; only valid if pSrv == NULL */
	unsigned char *pRemHostIP; /**< IP address of remote peer (currently used in server mode, only) */
	unsigned char *pRemHostName; /**< host name of remote peer (currently used in server mode, only) */
	int sock;	/**< the socket we use for regular, single-socket, operations */
	int *socks;	/**< the socket(s) we use for listeners, element 0 has nbr of socks */
	int iSessMax;	/**< maximum number of sessions permitted */
	/* variables for TLS support */
	uint8_t bEnableTLS;
	uint8_t bTLSActive;	/**< is TLS actually active (properly activated) on this session? */
	uint8_t bEnableTLSZip;
	int dhBits;	/**< number of bits for Diffie-Hellman key */
	char *pristring; /**< priority string for GnuTLS */
	relpAuthMode_t authmode;
	int connTimeout;
	tcpPermittedPeers_t permittedPeers;
	#ifdef ENABLE_TLS
	gnutls_anon_client_credentials_t anoncred;	/**< client anon credentials */
	gnutls_anon_server_credentials_t anoncredSrv;	/**< server anon credentials */
	/* GnuTLS certificat support */
	gnutls_certificate_credentials_t xcred;		/**< certificate credentials */
	#endif
	char *caCertFile;
	char *ownCertFile;
	char *privKeyFile;
	char *tlsConfigCmd;	/**< optional configuration command property for TLS libs **/
	#ifdef ENABLE_TLS
	gnutls_session_t session;
	gnutls_dh_params_t dh_params; /**< server DH parameters for anon mode */
	#endif
	#ifdef ENABLE_TLS_OPENSSL
	SSL *ssl;		/* OpenSSL main SSL obj */
	osslSslState_t sslState;/**< what must we retry? */
	#endif
	relpTcpRtryState_t rtryOp;
	#ifdef ENABLE_TLS_OPENSSL
	int rtryOsslErr;	/**< store optional ssl error code into like SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE */
	#endif
} relpTcp_t;

/* macros for quick member access */
#define relpTcpGetNumSocks(pThis)    ((pThis)->socks[0])
#define relpTcpGetLstnSock(pThis, i) ((pThis)->socks[i])
#define relpTcpGetSock(pThis)        ((pThis)->sock)

/* inlines (only for library-internal use!) */
static inline relpTcpRtryState_t
relpTcpRtryOp(relpTcp_t *pThis)
{
	return pThis->rtryOp;
}

/* prototypes */
relpRetVal relpTcpConstruct(relpTcp_t **ppThis, relpEngine_t *pEngine, int connType, void *pParent);
relpRetVal relpTcpDestruct(relpTcp_t **ppThis);
relpRetVal relpTcpAbortDestruct(relpTcp_t **ppThis);
relpRetVal relpTcpLstnInit(relpTcp_t *pThis, unsigned char *pLstnPort, unsigned char *pLstnAddr, int ai_family);
relpRetVal relpTcpAcceptConnReq(relpTcp_t **ppThis, int sock, relpSrv_t *pSrv);
relpRetVal relpTcpRcv(relpTcp_t *pThis, relpOctet_t *pRcvBuf, ssize_t *pLenBuf);
relpRetVal relpTcpSend(relpTcp_t *pThis, relpOctet_t *pBuf, ssize_t *pLenBuf);
relpRetVal relpTcpConnect(relpTcp_t *pThis, int family, unsigned char *port,
	unsigned char *host, unsigned char *clientIP);
relpRetVal relpTcpEnableTLS(relpTcp_t *pThis);
relpRetVal relpTcpEnableTLSZip(relpTcp_t *pThis);
relpRetVal relpTcpSetDHBits(relpTcp_t *pThis, int bits);
relpRetVal relpTcpSetGnuTLSPriString(relpTcp_t *pThis, char *pristr);
relpRetVal relpTcpSetCACert(relpTcp_t *pThis, char *cert);
relpRetVal relpTcpSetOwnCert(relpTcp_t *pThis, char *cert);
relpRetVal relpTcpSetPrivKey(relpTcp_t *pThis, char *cert);
relpRetVal relpTcpSetTlsConfigCmd(relpTcp_t *pThis, char *cfgcmd);
relpRetVal relpTcpSetPermittedPeers(relpTcp_t *pThis, relpPermittedPeers_t *pPeers);
relpRetVal LIBRELP_ATTR_NONNULL() relpTcpRtryHandshake(relpTcp_t *pThis);
relpRetVal relpTcpSetUsrPtr(relpTcp_t *pThis, void *pUsr);
relpRetVal relpTcpSetConnTimeout(relpTcp_t *pThis, int connTimeout);
relpRetVal relpTcpSetAuthMode(relpTcp_t *pThis, relpAuthMode_t authmode);
void relpTcpHintBurstBegin(relpTcp_t *pThis);
void relpTcpHintBurstEnd(relpTcp_t *pThis);
int LIBRELP_ATTR_NONNULL() relpTcpGetRtryDirection(relpTcp_t *pThis);
int relpTcpWaitWriteable(relpTcp_t *pThis, struct timespec *timeout);
void relpTcpExitTLS(void);
relpRetVal LIBRELP_ATTR_NONNULL() relpTcpDestructTLS(NOTLS_UNUSED relpTcp_t *pThis);

#ifdef ENABLE_TLS_OPENSSL
/*-----------------------------------------------------------------------------*/
#define MUTEX_TYPE       pthread_mutex_t
#define MUTEX_SETUP(x)   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define THREAD_ID        pthread_self()

/* This array will store all of the mutexes available to OpenSSL. */
struct CRYPTO_dynlock_value
{
	MUTEX_TYPE mutex;
};

void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
	__attribute__((unused)) const char *file, __attribute__((unused)) int line);
void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
	__attribute__((unused)) const char *file, __attribute__((unused)) int line);
struct CRYPTO_dynlock_value * dyn_create_function(
	__attribute__((unused)) const char *file, __attribute__((unused)) int line);
unsigned long id_function(void);
void locking_function(int mode, int n,
	__attribute__((unused)) const char * file, __attribute__((unused)) int line);

int opensslh_THREAD_setup(void);
int opensslh_THREAD_cleanup(void);
void relpTcpLastSSLErrorMsg(int ret, relpTcp_t *const pThis, const char* pszCallSource);
int verify_callback(int status, X509_STORE_CTX *store);
relpRetVal relpTcpChkPeerAuth(relpTcp_t *const pThis);
relpRetVal relpTcpPostHandshakeCheck(relpTcp_t *const pThis);
relpRetVal LIBRELP_ATTR_NONNULL(1) relpTcpSslInitCerts(relpTcp_t *const pThis, char *ownCertFile, char *privKeyFile);

/*-----------------------------------------------------------------------------*/
#endif

#endif /* #ifndef RELPTCP_H_INCLUDED */
