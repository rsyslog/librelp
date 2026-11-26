/* SPDX-License-Identifier: Apache-2.0 */

/* Runtime-compatible GnuTLS certificate fingerprint pin verification.
 *
 * Copyright 2026 by Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 */
#include "config.h"

#include "gnutls_fingerprint.h"

#if defined(ENABLE_TLS) && defined(HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)

#include <string.h>

/* GnuTLS used the MAC API for digest lookup before 3.2.2. The old matcher
 * used the same compatibility boundary. */
#if GNUTLS_VERSION_NUMBER < 0x030202
typedef gnutls_mac_algorithm_t fingerprintDigestId_t;
#define FINGERPRINT_DIGEST_UNKNOWN GNUTLS_MAC_UNKNOWN
#define FINGERPRINT_DIGEST_LOOKUP gnutls_mac_get_id
static const char *
fingerprintDigestGetName(const fingerprintDigestId_t id)
{
	return gnutls_mac_get_name(id);
}
#else
typedef gnutls_digest_algorithm_t fingerprintDigestId_t;
#define FINGERPRINT_DIGEST_UNKNOWN GNUTLS_DIG_UNKNOWN
#define FINGERPRINT_DIGEST_LOOKUP gnutls_digest_get_id
static const char *
fingerprintDigestGetName(const fingerprintDigestId_t id)
{
	return gnutls_digest_get_name(id);
}
#endif

#define MAX_FINGERPRINT_DIGESTS 10
#define MAX_FINGERPRINT_BYTES 126

static fingerprintDigestId_t
lookupPinDigest(const char *const pin)
{
	char name[32];
	size_t length;

	if(pin == NULL)
		return FINGERPRINT_DIGEST_UNKNOWN;
	length = strcspn(pin, ":");
	if(pin[length] == '\0')
		return FINGERPRINT_DIGEST_UNKNOWN;
	if(length >= sizeof(name))
		length = sizeof(name) - 1;
	memcpy(name, pin, length);
	name[length] = '\0';
	/* Some GnuTLS headers declare the lookup const. Call indirectly so the
	 * compiler preserves writes to the name buffer that the lookup reads. */
	fingerprintDigestId_t (*volatile lookup)(const char *) = FINGERPRINT_DIGEST_LOOKUP;
	return lookup(name);
}

static int
hexValue(const char c)
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Require the spelling that GnuTLS itself prints, including uppercase hex.
 * This retains the old string comparison semantics while comparing the
 * certificate and pin as bytes. */
static int
pinMatchesDigest(const char *const pin, const char *const digestName, const size_t nameLength,
	const unsigned char *const digest, const size_t digestLength)
{
	const char *cursor;
	size_t i;

	if(pin == NULL || strncmp(pin, digestName, nameLength) != 0 ||
	   pin[nameLength] != ':')
		return 0;
	cursor = pin + nameLength;
	for(i = 0; i < digestLength; ++i) {
		int high;
		int low;
		if(*cursor++ != ':' || cursor[0] == '\0' || cursor[1] == '\0')
			return 0;
		high = hexValue(cursor[0]);
		low = hexValue(cursor[1]);
		if(high < 0 || low < 0 || digest[i] != (unsigned char) ((high << 4) | low))
			return 0;
		cursor += 2;
	}
	return *cursor == '\0';
}

/* Keep the callback's diagnostic fingerprint in the same canonical form as
 * the historical GnuTLS path. This text is not used for pin comparison. */
static void
writeAuthInfo(const char *const digestName, const size_t nameLength,
	const unsigned char *const digest, const size_t digestLength, char *const output)
{
	static const char hexDigits[] = "0123456789ABCDEF";
	size_t position = nameLength;
	size_t i;

	memcpy(output, digestName, nameLength);
	for(i = 0; i < digestLength; ++i) {
		output[position++] = ':';
		output[position++] = hexDigits[digest[i] >> 4];
		output[position++] = hexDigits[digest[i] & 0x0f];
	}
	output[position] = '\0';
}

relpGnuTLSFingerprintResult_t
relpGnuTLSFingerprintCheck(gnutls_x509_crt_t cert, const size_t pinCount,
	relpGnuTLSFingerprintPinAt pinAt, const void *const context,
	char *const authInfo, const size_t authInfoLength, int *const gnutlsError)
{
	fingerprintDigestId_t seen[MAX_FINGERPRINT_DIGESTS];
	unsigned char digest[MAX_FINGERPRINT_BYTES];
	const char *digestName = NULL;
	size_t digestCount = 0;
	size_t digestLength = 0;
	size_t nameLength = 0;
	size_t requiredLength = 0;
	size_t i;

	if(authInfo != NULL && authInfoLength > 0)
		authInfo[0] = '\0';
	if(gnutlsError != NULL)
		*gnutlsError = GNUTLS_E_SUCCESS;
	if(cert == NULL || pinAt == NULL)
		return RELP_GNUTLS_FINGERPRINT_INVALID_POLICY;

	/* Try the first occurrence of each digest as we scan the prefixes, even
	 * when its pin text is malformed. The sorted set tracks membership only. */
	for(i = 0; i < pinCount && digestCount < MAX_FINGERPRINT_DIGESTS; ++i) {
		const fingerprintDigestId_t digestId = lookupPinDigest(pinAt(context, i));
		size_t position = 0;
		size_t j;
		int gnuRet;

		if(digestId == FINGERPRINT_DIGEST_UNKNOWN)
			continue;
		while(position < digestCount && seen[position] < digestId)
			++position;
		if(position < digestCount && seen[position] == digestId)
			continue;
		for(j = digestCount; j > position; --j)
			seen[j] = seen[j - 1];
		seen[position] = digestId;
		++digestCount;

		digestName = fingerprintDigestGetName(digestId);
		if(digestName == NULL)
			digestName = "0000";

		digestLength = sizeof(digest);
		gnuRet = gnutls_x509_crt_get_fingerprint(cert,
			(gnutls_digest_algorithm_t) digestId, digest, &digestLength);
		if(gnuRet != GNUTLS_E_SUCCESS) {
			if(gnutlsError != NULL)
				*gnutlsError = gnuRet;
			return RELP_GNUTLS_FINGERPRINT_ERROR;
		}
		nameLength = strlen(digestName);
		requiredLength = nameLength + 3 * digestLength + 1;

		/* Preserve the historical text limit even for callers with larger buffers. */
		if(requiredLength >= RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE)
			continue;
		for(j = 0; j < pinCount; ++j) {
			if(pinMatchesDigest(pinAt(context, j), digestName, nameLength, digest, digestLength))
				return RELP_GNUTLS_FINGERPRINT_MATCH;
		}
	}
	if(digestName != NULL && requiredLength < RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE &&
	   authInfo != NULL && requiredLength <= authInfoLength)
		writeAuthInfo(digestName, nameLength, digest, digestLength, authInfo);
	return RELP_GNUTLS_FINGERPRINT_NO_MATCH;
}

#else

typedef int relpGnuTLSFingerprintUnavailableWithoutVerifyCallback_t;

#endif /* ENABLE_TLS && HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION */
