/* SPDX-License-Identifier: Apache-2.0 */

/* Verify the fixed GnuTLS fingerprint policy against a known certificate. */
#include "config.h"

#if defined(ENABLE_TLS) && defined(HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "gnutls_fingerprint.h"

#ifndef TEST_CERT_DIR
#define TEST_CERT_DIR "tls-certs"
#endif

typedef struct {
	const char *const *pins;
	size_t count;
} pinList_t;

static const char *
pinAt(const void *const context, const size_t index)
{
	const pinList_t *const list = context;
	return index < list->count ? list->pins[index] : NULL;
}

static int
loadCertificate(gnutls_x509_crt_t *const cert)
{
	const char *const path = TEST_CERT_DIR "/cert.pem";
	FILE *file = fopen(path, "rb");
	unsigned char *data = NULL;
	long fileLength;
	gnutls_datum_t datum;
	int result = 0;

	if(file == NULL)
		return 0;
	if(fseek(file, 0, SEEK_END) != 0 || (fileLength = ftell(file)) <= 0 ||
	   (unsigned long) fileLength > UINT_MAX || fseek(file, 0, SEEK_SET) != 0)
		goto done;
	data = malloc((size_t) fileLength);
	if(data == NULL || fread(data, 1, (size_t) fileLength, file) != (size_t) fileLength)
		goto done;

	datum.data = data;
	datum.size = (unsigned int) fileLength;
	if(gnutls_x509_crt_init(cert) != GNUTLS_E_SUCCESS)
		goto done;
	if(gnutls_x509_crt_import(*cert, &datum, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit(*cert);
		*cert = NULL;
		goto done;
	}
	result = 1;

done:
	free(data);
	fclose(file);
	return result;
}

static int
expectResult(const char *const name, gnutls_x509_crt_t cert,
	const char *const *pins, const size_t pinCount,
	const relpGnuTLSFingerprintResult_t expected)
{
	const pinList_t list = { pins, pinCount };
	int gnutlsError = GNUTLS_E_SUCCESS;
	char authInfo[RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE];
	const relpGnuTLSFingerprintResult_t actual = relpGnuTLSFingerprintCheck(
		cert, list.count, pinAt, &list, authInfo, sizeof(authInfo), &gnutlsError);
	if(actual != expected) {
		fprintf(stderr, "%s: expected result %d, got %d (GnuTLS %d)\n",
			name, expected, actual, gnutlsError);
		return 0;
	}
	return 1;
}

static int
expectAuthInfo(const char *const name, gnutls_x509_crt_t cert,
	const char *const *pins, const size_t pinCount,
	const relpGnuTLSFingerprintResult_t expectedResult, const char *const expectedAuthInfo)
{
	const pinList_t list = { pins, pinCount };
	char authInfo[RELP_GNUTLS_FINGERPRINT_AUTHINFO_SIZE];
	int gnutlsError = GNUTLS_E_SUCCESS;
	const relpGnuTLSFingerprintResult_t actual = relpGnuTLSFingerprintCheck(
		cert, list.count, pinAt, &list, authInfo, sizeof(authInfo), &gnutlsError);
	if(actual != expectedResult || strcmp(authInfo, expectedAuthInfo) != 0) {
		fprintf(stderr, "%s: result %d (expected %d), authinfo '%s' (expected '%s'), GnuTLS %d\n",
			name, actual, expectedResult, authInfo, expectedAuthInfo, gnutlsError);
		return 0;
	}
	return 1;
}

int
main(void)
{
	static const char sha1[] =
		"SHA1:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	static const char sha256[] =
		"SHA256:1E:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6";
	static const char sha384[] =
		"SHA384:54:0D:0D:16:C0:8D:65:F4:FF:E8:52:9F:A9:4A:92:B8:D6:7B:A6:21:B2:EF:E5:C7:D8:59:F3:D9:89:54:E1:D8:8C:A5:9A:19:BD:1E:9B:F8:3C:CD:5F:79:8E:40:06:46";
	static const char sha512[] =
		"SHA512:E6:CB:A0:1E:10:15:D4:B8:AE:3A:04:E1:0A:BA:0A:07:D2:3F:36:BA:66:4C:2D:C8:2A:AE:5E:5A:4C:B3:13:A0:7B:BC:EE:BF:1D:09:0C:BB:6B:79:46:58:36:DF:35:B1:B2:EE:07:C2:6B:6F:68:2B:B4:B2:4C:0D:4C:20:17:31";
	static const char wrongSha1[] =
		"SHA1:00:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	static const char wrongSha256[] =
		"SHA256:00:8F:A1:97:BF:96:8F:A7:27:C3:8F:07:81:1E:C8:B1:32:BD:BD:ED:07:A1:48:C4:BC:83:CE:BD:62:F8:DD:F6";
	static const char malformed[] = "SHA1:GG:C6";
	static const char unsupported[] = "MD5:5C:C6:62:D5:9D:25:9F:BC:F3:CB:61:FA:D2:B3:8B:61:88:D7:06:C3";
	static const char lowerHex[] =
		"SHA1:5c:c6:62:d5:9d:25:9f:bc:f3:cb:61:fa:d2:b3:8b:61:88:d7:06:c3";
	const char *onePin[1];
	const char *twoPins[2];
	gnutls_x509_crt_t cert = NULL;
	int ok = 1;

	if(gnutls_global_init() != GNUTLS_E_SUCCESS || !loadCertificate(&cert)) {
		fputs("failed to initialize GnuTLS or load test certificate\n", stderr);
		return EXIT_FAILURE;
	}

	onePin[0] = sha1;
	ok &= expectResult("SHA1 compatibility", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = sha256;
	ok &= expectResult("SHA256", cert, onePin, 1, RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = sha384;
	ok &= expectResult("SHA384", cert, onePin, 1, RELP_GNUTLS_FINGERPRINT_MATCH);
	onePin[0] = sha512;
	ok &= expectResult("SHA512", cert, onePin, 1, RELP_GNUTLS_FINGERPRINT_MATCH);

	twoPins[0] = wrongSha1;
	twoPins[1] = sha256;
	ok &= expectResult("mixed order SHA1 then SHA256", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = sha512;
	twoPins[1] = wrongSha1;
	ok &= expectResult("mixed order SHA512 then SHA1", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_MATCH);
	twoPins[0] = wrongSha1;
	twoPins[1] = wrongSha256;
	ok &= expectAuthInfo("valid pins with no match", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha256);
	onePin[0] = wrongSha1;
	ok &= expectAuthInfo("SHA1 mismatch authinfo", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha1);
	onePin[0] = wrongSha256;
	ok &= expectAuthInfo("SHA256 mismatch authinfo", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_NO_MATCH, sha256);

	twoPins[0] = sha1;
	twoPins[1] = unsupported;
	ok &= expectAuthInfo("unsupported pin after matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_INVALID_POLICY, "");
	twoPins[0] = unsupported;
	twoPins[1] = sha1;
	ok &= expectResult("unsupported pin before matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_INVALID_POLICY);
	twoPins[0] = sha1;
	twoPins[1] = malformed;
	ok &= expectResult("malformed pin after matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_INVALID_POLICY);
	twoPins[0] = malformed;
	twoPins[1] = sha1;
	ok &= expectResult("malformed pin before matching pin", cert, twoPins, 2,
		RELP_GNUTLS_FINGERPRINT_INVALID_POLICY);
	onePin[0] = lowerHex;
	ok &= expectResult("non-canonical lowercase hex", cert, onePin, 1,
		RELP_GNUTLS_FINGERPRINT_INVALID_POLICY);
	ok &= expectResult("empty policy", cert, NULL, 0,
		RELP_GNUTLS_FINGERPRINT_INVALID_POLICY);

	gnutls_x509_crt_deinit(cert);
	gnutls_global_deinit();
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else

int
main(void)
{
	return EXIT_SUCCESS;
}

#endif
