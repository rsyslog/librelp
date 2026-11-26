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

#define RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE 199

/* GnuTLS fingerprint pins use the exact uppercase forms SHA1, SHA256, SHA384,
 * or SHA512 followed by a colon and colon-separated uppercase hex bytes. Use
 * SHA256 for new pins; SHA1 remains accepted for existing pins. A malformed
 * or unsupported pin rejects the complete allowlist, even if another entry
 * would match.
 *
 * Check a complete fingerprint allowlist before accepting any matching pin.
 * The callback lets callers supply pins from their existing storage without
 * allocating a second list. gnutlsError is set only for digest API failures.
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
