/* SPDX-License-Identifier: Apache-2.0 */

/* GnuTLS certificate fingerprint pin verification (interface).
 *
 * Copyright 2026 by Adiscon GmbH.
 *
 * This file is part of librelp.
 *
 * Licensed under the Apache License, Version 2.0.
 * See COPYING.ASL20 for the license text.
 */
#ifndef RELP_GNUTLS_FINGERPRINT_H_INCLUDED
#define RELP_GNUTLS_FINGERPRINT_H_INCLUDED

#if defined(ENABLE_TLS) && defined(HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)

#include <stddef.h>
#include <gnutls/x509.h>

typedef const char *(*relpGnuTLSFingerprintPinAt)(const void *context, size_t index);

typedef enum {
	RELP_GNUTLS_FINGERPRINT_MATCH,
	RELP_GNUTLS_FINGERPRINT_NO_MATCH,
	RELP_GNUTLS_FINGERPRINT_INVALID_ARGUMENT,
	RELP_GNUTLS_FINGERPRINT_ERROR
} relpGnuTLSFingerprintResult_t;

#define RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE 256

/* Check a peer certificate against a list of fingerprint pins.
 *
 * A pin is "<NAME>:<HH>:<HH>:...", where NAME is the canonical name of any
 * digest the active GnuTLS runtime offers (for example SHA1, SHA256, SHA512)
 * and HH are uppercase hex bytes. SHA256 or stronger is recommended for new
 * pins; SHA1 remains accepted for existing configurations. Unknown names,
 * other spellings and malformed entries never match and do not invalidate
 * other pins. Each digest named by a pin is computed at most once.
 *
 * pinAt lets callers supply pins from their existing storage. On NO_MATCH,
 * authInfo receives the peer fingerprint for the digest whose first pin
 * appears last in the list (empty if no pin names a usable digest). ERROR is
 * returned only if no digest could be computed; gnutlsError then holds the
 * first GnuTLS error. INVALID_ARGUMENT means cert or pinAt was NULL.
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
