/* SPDX-License-Identifier: Apache-2.0 */

#ifndef RELP_GNUTLS_FINGERPRINT_H_INCLUDED
#define RELP_GNUTLS_FINGERPRINT_H_INCLUDED

#if defined(ENABLE_TLS) && defined(HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)

#include <stddef.h>
#include <gnutls/x509.h>

typedef const char *(*relpGnuTLSFingerprintPinAt)(const void *context, size_t index);

typedef enum {
	RELP_GNUTLS_FINGERPRINT_MATCH,
	RELP_GNUTLS_FINGERPRINT_NO_MATCH,
	RELP_GNUTLS_FINGERPRINT_INVALID_POLICY,
	RELP_GNUTLS_FINGERPRINT_ERROR
} relpGnuTLSFingerprintResult_t;

#define RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE 256

/* GnuTLS fingerprint pins use any digest name recognized by the active
 * GnuTLS runtime, followed by a colon and the canonical uppercase colon-hex
 * fingerprint. SHA1 and additional runtime-supported digest names remain
 * available when GnuTLS recognizes them. Unknown and malformed entries do
 * not match and do not invalidate valid siblings. Only the first ten distinct
 * recognized digest IDs are considered, in their order of appearance; a
 * recognized but malformed entry still consumes its digest's slot.
 *
 * Digests are computed in that same order and only as needed. The callback
 * lets callers supply pins from their existing storage without allocating a
 * second list. With no match, authInfo receives the last attempted fingerprint
 * if it fits. Otherwise authInfo is empty. gnutlsError reports digest API failures.
 */
relpGnuTLSFingerprintResult_t relpGnuTLSFingerprintCheck(
	gnutls_x509_crt_t cert,
	size_t pinCount,
	relpGnuTLSFingerprintPinAt pinAt,
	const void *context,
	char *authInfo,
	size_t authInfoLength,
	int *gnutlsError);

#endif /* ENABLE_TLS && HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION */

#endif /* RELP_GNUTLS_FINGERPRINT_H_INCLUDED */
