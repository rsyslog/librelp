/* SPDX-License-Identifier: Apache-2.0 */

/* Fixed-profile certificate fingerprint pin verification.
 *
 * Copyright 2026 by Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 *
 * The accepted algorithms are explicit to keep pin policy reviewable and to
 * avoid silently changing the allowlist when a TLS library adds algorithms.
 */
#include "config.h"

#include "gnutls_fingerprint.h"

#if defined(ENABLE_TLS) && defined(HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)

#include <string.h>

typedef struct {
	const char *name;
	size_t nameLength;
	size_t digestLength;
	gnutls_digest_algorithm_t algorithm;
} fingerprintAlgorithm_t;

static const fingerprintAlgorithm_t algorithms[] = {
	{ "SHA1", 4, 20, GNUTLS_DIG_SHA1 },
	{ "SHA256", 6, 32, GNUTLS_DIG_SHA256 },
	{ "SHA384", 6, 48, GNUTLS_DIG_SHA384 },
	{ "SHA512", 6, 64, GNUTLS_DIG_SHA512 }
};

#define FINGERPRINT_ALGORITHM_COUNT (sizeof(algorithms) / sizeof(algorithms[0]))
#define MAX_FINGERPRINT_BYTES 64

typedef struct {
	size_t algorithmIndex;
	unsigned char bytes[MAX_FINGERPRINT_BYTES];
} parsedFingerprint_t;

static int
hexValue(const char c)
{
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int
hasExpectedLength(const char *const text, const size_t expectedLength)
{
	size_t i;
	for(i = 0; i < expectedLength; ++i) {
		if(text[i] == '\0')
			return 0;
	}
	return text[expectedLength] == '\0';
}

static int
parseFingerprint(const char *const pin, parsedFingerprint_t *const parsed)
{
	const fingerprintAlgorithm_t *algorithm = NULL;
	const char *cursor;
	size_t i;

	if(pin == NULL)
		return 0;

	for(i = 0; i < FINGERPRINT_ALGORITHM_COUNT; ++i) {
		if(strncmp(pin, algorithms[i].name, algorithms[i].nameLength) == 0 &&
		   pin[algorithms[i].nameLength] == ':') {
			algorithm = &algorithms[i];
			parsed->algorithmIndex = i;
			break;
		}
	}
	if(algorithm == NULL ||
	   !hasExpectedLength(pin, algorithm->nameLength + 3 * algorithm->digestLength))
		return 0;

	cursor = pin + algorithm->nameLength + 1;
	for(i = 0; i < algorithm->digestLength; ++i) {
		const int high = hexValue(cursor[0]);
		const int low = hexValue(cursor[1]);
		if(high < 0 || low < 0)
			return 0;
		parsed->bytes[i] = (unsigned char)((high << 4) | low);
		cursor += 2;
		if(i + 1 < algorithm->digestLength) {
			if(*cursor != ':')
				return 0;
			++cursor;
		}
	}
	return 1;
}

static int
fingerprintsEqual(const unsigned char *const left, const unsigned char *const right,
	const size_t length)
{
	unsigned char difference = 0;
	size_t i;
	for(i = 0; i < length; ++i)
		difference |= left[i] ^ right[i];
	return difference == 0;
}

/* Produce the existing callback's colon-hex credential text. This is only
 * used after a valid policy fails to match; pin verification compares bytes.
 */
static int
formatFingerprint(const size_t algorithmIndex, const unsigned char *const digest,
	char *const output, const size_t outputLength)
{
	static const char hexDigits[] = "0123456789ABCDEF";
	const fingerprintAlgorithm_t *const algorithm = &algorithms[algorithmIndex];
	const size_t requiredLength = algorithm->nameLength + 3 * algorithm->digestLength + 1;
	size_t position = algorithm->nameLength;
	size_t i;

	if(output == NULL || outputLength < requiredLength)
		return 0;
	memcpy(output, algorithm->name, algorithm->nameLength);
	output[position++] = ':';
	for(i = 0; i < algorithm->digestLength; ++i) {
		output[position++] = hexDigits[digest[i] >> 4];
		output[position++] = hexDigits[digest[i] & 0x0f];
		if(i + 1 < algorithm->digestLength)
			output[position++] = ':';
	}
	output[position] = '\0';
	return 1;
}

relpGnuTLSFingerprintResult_t
relpGnuTLSFingerprintCheck(gnutls_x509_crt_t cert, const size_t pinCount,
	relpGnuTLSFingerprintPinAt pinAt, const void *const context,
	char *const authInfo, const size_t authInfoLength, int *const gnutlsError)
{
	unsigned char digestValues[FINGERPRINT_ALGORITHM_COUNT][MAX_FINGERPRINT_BYTES] = {{0}};
	unsigned char algorithmNeeded[FINGERPRINT_ALGORITHM_COUNT] = {0};
	parsedFingerprint_t parsed;
	size_t i;
	int gnuRet;

	if(authInfo != NULL && authInfoLength > 0)
		authInfo[0] = '\0';
	if(gnutlsError != NULL)
		*gnutlsError = GNUTLS_E_SUCCESS;
	if(cert == NULL || pinAt == NULL || pinCount == 0)
		return RELP_GNUTLS_FINGERPRINT_INVALID_POLICY;

	/* Reject the whole policy before computing any digest. A valid matching pin
	 * cannot mask an unsupported or malformed entry elsewhere in the list.
	 */
	for(i = 0; i < pinCount; ++i) {
		if(!parseFingerprint(pinAt(context, i), &parsed))
			return RELP_GNUTLS_FINGERPRINT_INVALID_POLICY;
		algorithmNeeded[parsed.algorithmIndex] = 1;
	}
	const size_t diagnosticAlgorithmIndex = parsed.algorithmIndex;

	/* Each digest selected by the validated policy is calculated once. */
	for(i = 0; i < FINGERPRINT_ALGORITHM_COUNT; ++i) {
		size_t digestLength;
		if(!algorithmNeeded[i])
			continue;
		digestLength = algorithms[i].digestLength;
		gnuRet = gnutls_x509_crt_get_fingerprint(cert, algorithms[i].algorithm,
			digestValues[i], &digestLength);
		if(gnuRet != GNUTLS_E_SUCCESS) {
			if(gnutlsError != NULL)
				*gnutlsError = gnuRet;
			return RELP_GNUTLS_FINGERPRINT_ERROR;
		}
		if(digestLength != algorithms[i].digestLength) {
			if(gnutlsError != NULL)
				*gnutlsError = GNUTLS_E_CERTIFICATE_ERROR;
			return RELP_GNUTLS_FINGERPRINT_ERROR;
		}
	}

	for(i = 0; i < pinCount; ++i) {
		const fingerprintAlgorithm_t *algorithm;
		if(!parseFingerprint(pinAt(context, i), &parsed))
			return RELP_GNUTLS_FINGERPRINT_INVALID_POLICY;
		algorithm = &algorithms[parsed.algorithmIndex];
		if(fingerprintsEqual(parsed.bytes, digestValues[parsed.algorithmIndex],
			algorithm->digestLength))
			return RELP_GNUTLS_FINGERPRINT_MATCH;
	}
	(void) formatFingerprint(diagnosticAlgorithmIndex,
		digestValues[diagnosticAlgorithmIndex], authInfo, authInfoLength);
	return RELP_GNUTLS_FINGERPRINT_NO_MATCH;
}

#else

typedef int relpGnuTLSFingerprintUnavailableWithoutVerifyCallback_t;

#endif /* ENABLE_TLS && HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION */
