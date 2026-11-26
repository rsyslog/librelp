/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Optional multi-digest GnuTLS fingerprint verification.
 *
 * Copyright 2008-2025 by Rainer Gerhards and Adiscon GmbH.
 * Copyright 2018 briaeros <briaeros@users.noreply.github.com>
 * Copyright 2022 alakatos <alakatos@redhat.com>
 *
 * This internal unit preserves the GnuTLS digest selection and fingerprint
 * formatting contribution from librelp commit
 * d3b58a58aa5911b24645126d14b06b3f3af89c0f, including the formatter
 * terminator fix from commit 6704009c1fa7daa1997fa05297e9b99dd4e9f974.
 * Keep this optional unit separate from code selected for the Apache License
 * 2.0 profile.
 *
 * This file is part of librelp.
 *
 * Librelp is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Librelp is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with librelp. If not, see <https://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 *
 * If the terms of the GPL are unsuitable for your needs, you may obtain a
 * commercial license from Adiscon. Contact sales@adiscon.com for further
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

#include <stdio.h>
#include <string.h>

#include "gnutlsfingerprint.h"

#if GNUTLS_VERSION_NUMBER < 0x030202
/* gnutls_mac_algorithm_t and gnutls_digest_algorithm_t are aligned. */
typedef gnutls_mac_algorithm_t digest_id_t;
static digest_id_t digest_get_id(const char *name)
{
	return gnutls_mac_get_id(name);
}
static const char *digest_get_name(digest_id_t id)
{
	return gnutls_mac_get_name(id);
}
#define UNK_DIGEST GNUTLS_MAC_UNKNOWN
#else
typedef gnutls_digest_algorithm_t digest_id_t;
static digest_id_t digest_get_id(const char *name)
{
	return gnutls_digest_get_id(name);
}
static const char *digest_get_name(digest_id_t id)
{
	return gnutls_digest_get_name(id);
}
#define UNK_DIGEST GNUTLS_DIG_UNKNOWN
#endif

/* The caller supplies a buffer large enough for the fingerprint text. */
static void
GenFingerprintStr(const char *pFingerprint, const int sizeFingerprint,
	char *fpBuf, const size_t bufLen, const digest_id_t type,
	relpEngine_t *pEngine)
{
	int iSrc, iDst;
	size_t sizeTotal = 0, sizeDigest = 0;
	const char *digestType = digest_get_name(type);

	if(digestType == NULL) {
		if(pEngine != NULL)
			pEngine->dbgprint((char*)"warn : the signature type %d is unknown\n", type);
		digestType = "0000";
	}
	sizeDigest = strlen(digestType);
	/* Check the byte count before multiplying, and reserve one byte for NUL. */
	if(sizeFingerprint >= 0 && bufLen > sizeDigest &&
		(size_t)sizeFingerprint <= (bufLen - sizeDigest - 1) / 3) {
		sizeTotal = sizeDigest + ((size_t)sizeFingerprint * 3);
		strncpy(fpBuf, digestType, sizeDigest);
		iDst = sizeDigest;
		for(iSrc = 0; iSrc < sizeFingerprint; ++iSrc, iDst += 3)
			sprintf(fpBuf + iDst, ":%2.2X", (unsigned char)pFingerprint[iSrc]);
		fpBuf[sizeTotal] = '\0';
	} else if(bufLen >= 1) {
		if(pEngine != NULL)
			pEngine->dbgprint((char*)"warn: buffer overflow for %s signature\n", digestType);
		fpBuf[0] = '\0';
	} else if(pEngine != NULL) {
		pEngine->dbgprint((char*)"warn: buffer empty, unable to print the signature\n");
	}
}

#define MAX_DIGEST_PEER 10
static size_t
ListDigestPeer(digest_id_t *listSigPeer, tcpPermittedPeers_t *listPeers,
	relpEngine_t *pEngine)
{
	int i;
	int maxDigest = 0;
	char digest[32];

	if(listPeers == NULL || listPeers->nmemb <= 0) {
		if(pEngine != NULL)
			pEngine->dbgprint((char*)"warn: no PermittedPeer listed\n");
		return 0;
	}
	for(i = 0; i < listPeers->nmemb; ++i) {
		if(listPeers->peer[i].name != NULL) {
			char *eow = strchr(listPeers->peer[i].name, ':');
			if(eow != NULL) {
				int sizeDigest = (int)(eow - listPeers->peer[i].name);
				digest_id_t actualDigest;
				sizeDigest = sizeDigest > 31 ? 31 : sizeDigest;
				strncpy(digest, listPeers->peer[i].name, sizeDigest);
				digest[sizeDigest] = '\0';
				actualDigest = digest_get_id(digest);
				if(actualDigest != UNK_DIGEST) {
					int alreadyExist = 0;
					int j;
					for(j = 0; j < maxDigest && alreadyExist == 0 &&
						j < MAX_DIGEST_PEER; ++j) {
						if(listSigPeer[j] == actualDigest)
							alreadyExist = 1;
					}
					if(maxDigest < MAX_DIGEST_PEER && alreadyExist == 0) {
						if(pEngine != NULL)
							pEngine->dbgprint((char*)"DDDD: adding digest %s\n", digest);
						listSigPeer[maxDigest++] = actualDigest;
					}
				}
			}
		}
	}
	return maxDigest;
}

relpGnuTlsFingerprintResult_t
relpGnuTlsFingerprintCheck(gnutls_x509_crt_t cert,
	tcpPermittedPeers_t *listPeers, relpEngine_t *pEngine,
	char *fpPrintable, size_t fpPrintableSize, int *pGnuRet)
{
	char fingerprint[126];
	digest_id_t listSigPeer[MAX_DIGEST_PEER];
	size_t maxDigest, k, size;
	int i;
	int found = 0;
	int r = GNUTLS_E_SUCCESS;

	if(fpPrintableSize > 0)
		fpPrintable[0] = '\0';
	if(pGnuRet != NULL)
		*pGnuRet = GNUTLS_E_SUCCESS;
	maxDigest = ListDigestPeer(listSigPeer, listPeers, pEngine);
	for(k = 0; k < maxDigest && found == 0; ++k) {
		digest_id_t digest = listSigPeer[k];
		size = sizeof(fingerprint);
		r = gnutls_x509_crt_get_fingerprint(cert,
			(gnutls_digest_algorithm_t)digest, fingerprint, &size);
		if(r != GNUTLS_E_SUCCESS) {
			if(pGnuRet != NULL)
				*pGnuRet = r;
			return relpGnuTlsFingerprintDigestError;
		}
		GenFingerprintStr(fingerprint, (int)size, fpPrintable,
			fpPrintableSize, digest, pEngine);
		pEngine->dbgprint((char*)"peer's certificate %s fingerprint: %s\n",
			digest_get_name(digest), fpPrintable);

		pEngine->dbgprint((char*)"n peers %d\n", listPeers->nmemb);
		for(i = 0; i < listPeers->nmemb; ++i) {
			pEngine->dbgprint((char*)"checking peer '%s','%s'\n",
				fpPrintable, listPeers->peer[i].name);
			if(!strcmp(fpPrintable, listPeers->peer[i].name)) {
				found = 1;
				break;
			}
		}
	}
	return found ? relpGnuTlsFingerprintMatch : relpGnuTlsFingerprintNoMatch;
}
