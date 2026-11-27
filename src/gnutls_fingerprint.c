/* SPDX-License-Identifier: Apache-2.0 */

/* GnuTLS certificate fingerprint pin verification.
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

/* GnuTLS used the MAC API for digest enumeration before 3.2.2. */
#if GNUTLS_VERSION_NUMBER < 0x030202
typedef gnutls_mac_algorithm_t fingerprintDigestId_t;
#define FINGERPRINT_DIGEST_UNKNOWN GNUTLS_MAC_UNKNOWN
static const fingerprintDigestId_t *
fingerprintDigestList(void)
{
	return gnutls_mac_list();
}
static const char *
fingerprintDigestGetName(const fingerprintDigestId_t id)
{
	return gnutls_mac_get_name(id);
}
#else
typedef gnutls_digest_algorithm_t fingerprintDigestId_t;
#define FINGERPRINT_DIGEST_UNKNOWN GNUTLS_DIG_UNKNOWN
static const fingerprintDigestId_t *
fingerprintDigestList(void)
{
	return gnutls_digest_list();
}
static const char *
fingerprintDigestGetName(const fingerprintDigestId_t id)
{
	return gnutls_digest_get_name(id);
}
#endif

/* Twice the largest digest GnuTLS currently offers (64 bytes for SHA512 and
 * SHA3-512). If a digest does not fit, GnuTLS reports an error and pins
 * naming that digest cannot match. */
#define MAX_FINGERPRINT_BYTES 128

/* A pin has the form "<NAME>:<HH>:<HH>:...", where NAME is exactly the
 * canonical digest name GnuTLS reports and HH are uppercase hex bytes. This is
 * the form librelp has always printed and accepted.
 *
 * Names are resolved by comparing against the canonical names in the runtime
 * digest list instead of calling gnutls_digest_get_id(). Besides needing no
 * temporary buffer, this avoids a GnuTLS header issue: the lookup functions are
 * declared __attribute__((const)), which allows compilers to drop the writes
 * to a buffer passed to them. Aliases and other spellings were never able to
 * match because the comparison always used the canonical name. */
static int
pinHasDigestName(const char *const pin, const char *const name, const size_t nameLength)
{
	return pin != NULL && strncmp(pin, name, nameLength) == 0 && pin[nameLength] == ':';
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

/* The caller has verified the "<NAME>:" prefix. Compare the colon-hex body
 * with the digest bytes. Each byte position is read only after the previous
 * one was found to be non-NUL, so the scan never passes the terminator. */
static int
pinMatchesDigest(const char *const pin, const size_t nameLength,
	const unsigned char *const digest, const size_t digestLength)
{
	const char *cursor = pin + nameLength;
	size_t i;

	for(i = 0; i < digestLength; ++i) {
		int high;
		int low;
		if(cursor[0] != ':' || cursor[1] == '\0' || cursor[2] == '\0')
			return 0;
		high = hexValue(cursor[1]);
		low = hexValue(cursor[2]);
		if(high < 0 || low < 0 || digest[i] != (unsigned char) ((high << 4) | low))
			return 0;
		cursor += 3;
	}
	return *cursor == '\0';
}

/* Format the peer fingerprint for the auth error callback. This text is for
 * diagnostics only; pin verification never compares formatted text. */
static void
writeAuthInfo(const char *const name, const size_t nameLength,
	const unsigned char *const digest, const size_t digestLength,
	char *const output, const size_t outputLength)
{
	static const char hexDigits[] = "0123456789ABCDEF";
	size_t position = nameLength;
	size_t i;

	if(output == NULL || outputLength == 0 ||
	   nameLength >= outputLength || digestLength > (outputLength - nameLength - 1) / 3)
		return;
	memcpy(output, name, nameLength);
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
	const fingerprintDigestId_t *digestIds;
	unsigned char digest[MAX_FINGERPRINT_BYTES];
	unsigned char reportDigest[MAX_FINGERPRINT_BYTES];
	const char *reportName = NULL;
	size_t reportNameLength = 0;
	size_t reportDigestLength = 0;
	size_t reportPinIndex = 0;
	int firstError = GNUTLS_E_SUCCESS;
	size_t d;

	if(authInfo != NULL && authInfoLength > 0)
		authInfo[0] = '\0';
	if(gnutlsError != NULL)
		*gnutlsError = GNUTLS_E_SUCCESS;
	if(cert == NULL || pinAt == NULL)
		return RELP_GNUTLS_FINGERPRINT_INVALID_ARGUMENT;
	digestIds = fingerprintDigestList();
	if(digestIds == NULL || pinCount == 0)
		return RELP_GNUTLS_FINGERPRINT_NO_MATCH;

	/* Every digest named by at least one pin is computed exactly once, so the
	 * work per handshake is bounded by the runtime's digest list rather than
	 * by the configuration. Pins with unknown names, aliases or malformed
	 * bodies never match and never invalidate other pins. A digest that
	 * GnuTLS cannot compute only disables the pins naming it. */
	for(d = 0; digestIds[d] != FINGERPRINT_DIGEST_UNKNOWN; ++d) {
		const char *const name = fingerprintDigestGetName(digestIds[d]);
		size_t nameLength;
		size_t digestLength;
		size_t firstPin = 0;
		int needed = 0;
		int gnuRet;
		size_t i;

		if(name == NULL || name[0] == '\0')
			continue;
		nameLength = strlen(name);
		for(i = 0; i < pinCount; ++i) {
			if(pinHasDigestName(pinAt(context, i), name, nameLength)) {
				firstPin = i;
				needed = 1;
				break;
			}
		}
		if(!needed)
			continue;

		digestLength = sizeof(digest);
		gnuRet = gnutls_x509_crt_get_fingerprint(cert,
			(gnutls_digest_algorithm_t) digestIds[d], digest, &digestLength);
		if(gnuRet != GNUTLS_E_SUCCESS || digestLength == 0 ||
		   digestLength > sizeof(digest)) {
			if(firstError == GNUTLS_E_SUCCESS)
				firstError = gnuRet != GNUTLS_E_SUCCESS ? gnuRet : GNUTLS_E_INTERNAL_ERROR;
			continue;
		}

		for(i = firstPin; i < pinCount; ++i) {
			const char *const pin = pinAt(context, i);
			if(pinHasDigestName(pin, name, nameLength) &&
			   pinMatchesDigest(pin, nameLength, digest, digestLength))
				return RELP_GNUTLS_FINGERPRINT_MATCH;
		}

		/* For a mismatch, report the digest whose first pin appears last in
		 * the configuration, as the previous implementation did. */
		if(reportName == NULL || firstPin > reportPinIndex) {
			reportName = name;
			reportNameLength = nameLength;
			reportPinIndex = firstPin;
			reportDigestLength = digestLength;
			memcpy(reportDigest, digest, digestLength);
		}
	}

	if(reportName != NULL) {
		writeAuthInfo(reportName, reportNameLength, reportDigest, reportDigestLength,
			authInfo, authInfoLength);
		return RELP_GNUTLS_FINGERPRINT_NO_MATCH;
	}
	if(firstError != GNUTLS_E_SUCCESS) {
		if(gnutlsError != NULL)
			*gnutlsError = firstError;
		return RELP_GNUTLS_FINGERPRINT_ERROR;
	}
	return RELP_GNUTLS_FINGERPRINT_NO_MATCH;
}

#else

typedef int relpGnuTLSFingerprintUnavailableWithoutVerifyCallback_t;

#endif /* ENABLE_TLS && HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION */
